-- @lib: rbac
-- @category: security
-- @desc: Quack RBAC 策略引擎 v3（演示策略）——protected = secret_data / public_data / other_data；
--        全目录 default-deny + RBAC 元数据恒拒 + 函数黑名单。挂 quack authn/authz 钩子。
-- @source: original（duckdb-luajit 系列）
-- @requires: _duckdb_query（普通模式；trusted 沙箱下不可用）
--
-- 与 rbac_mimic.lua 完全同引擎（v3），仅 protected 清单不同。
-- 安全模型说明、v3 修复项（大小写/全目录 default-deny/元数据恒拒/函数黑名单/堆叠语句）、
-- 已知残留（字面量误拒）—— 全部见 rbac_mimic.lua 头部注释。
--
-- 重要：v2 的"sample 未把元数据表列入 protected → 可 dump quack_tokens"漏洞
-- 在 v3 中由 META_TABLES 恒拒结构性修复，与 protected 清单无关。
--
-- 表模型 / 挂钩 / 调用：同 rbac_mimic.lua。

local CONFIG = {
  tokens_table   = 'quack_tokens',
  sessions_table = 'quack_sessions',
  roles_table    = 'user_roles',
  perms_table    = 'role_perms',
  -- 演示受控表：secret_data(机密) / public_data(公开) / other_data(未授权演示表，验证 default-deny)
  protected      = { 'secret_data', 'public_data', 'other_data' },
  allow_write    = false,  -- true = 放行写语句并按 can_write 细粒度授权；false = 一切写语句拒绝（推荐）
  strict_write   = true,   -- true = WITH 开头且含写关键字一律拒绝（合法 CTE 读放行）
  audit_table    = nil,    -- 设 'rbac_audit' 则 authz 每次决策记审计（每查询多一次写，性能敏感慎用）
}

local META_TABLES = {
  [CONFIG.tokens_table]   = true,
  [CONFIG.sessions_table] = true,
  [CONFIG.roles_table]    = true,
  [CONFIG.perms_table]    = true,
}
local CATALOG_BLOCK = { 'INFORMATION_SCHEMA', 'PG_CATALOG', 'DUCKDB_CATALOG' }
local BLOCKED_TOKENS = {
  { t = 'LUAJIT_S',     prefix = false },
  { t = 'LUAJIT_QUERY', prefix = false },
  { t = 'LUAJIT_MODULE', prefix = false },
  { t = 'LUAJIT(',      prefix = false },
  { t = 'INSTALL',      prefix = false },
  { t = 'LOAD',         prefix = true  },
  { t = 'ATTACH',       prefix = false },
  { t = 'DETACH',       prefix = false },
  { t = 'PRAGMA',       prefix = false },
  { t = 'SET GLOBAL',   prefix = false },
  { t = 'DUCKDB_',      prefix = true  },
}
local MID_WRITE_KWS = { 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'CREATE', 'DROP',
                        'ALTER', 'COPY', 'EXECUTE', 'CALL', 'TRUNCATE' }

local READ_KWS  = { 'SELECT', 'FROM', 'WITH', 'EXPLAIN', 'DESCRIBE', 'SHOW', 'VALUES', 'TABLE', 'SUMMARIZE' }
local WRITE_KWS = { 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'COPY', 'CREATE', 'DROP', 'ALTER', 'SET', 'CALL',
                    'ATTACH', 'DETACH', 'EXPORT', 'IMPORT', 'CHECKPOINT', 'VACUUM', 'COMMENT', 'INSTALL',
                    'LOAD', 'PREPARE', 'EXECUTE', 'USE', 'GRANT', 'REVOKE', 'TRUNCATE' }

local function esc(s)
  return (s:gsub("'", "''"))
end

local function q(rows, i, col)
  return rows and rows[i] and rows[i][col]
end

local function text_has(needle, hay, prefix)
  local i = 1
  while true do
    local s = hay:find(needle, i, true)
    if not s then return false end
    local prev_ok = (s == 1) or (hay:sub(s - 1, s - 1):match('[%w_]') == nil)
    if prev_ok then
      if prefix then return true end
      local e = s + #needle - 1
      local next_ok = (e == #hay) or (hay:sub(e + 1, e + 1):match('[%w_]') == nil)
      if next_ok then return true end
    end
    i = s + 1
  end
end

local function classify(up)
  for _, kw in ipairs(READ_KWS) do
    if up:find('^' .. kw) then return 'read' end
  end
  for _, kw in ipairs(WRITE_KWS) do
    if up:find('^' .. kw) then return 'write' end
  end
  return 'unknown'  -- 未识别前缀：拒绝
end

local function resolve_user(sid)
  local u = _duckdb_query("SELECT user_name FROM " .. CONFIG.sessions_table .. " WHERE sid = '" .. esc(sid or '') .. "'")
  return q(u, 1, 'user_name')
end

local function user_has_perm(user, tbl, need_write)
  local col = need_write and 'can_write' or 'can_select'
  local r = _duckdb_query(
    "SELECT COUNT(*) AS n FROM " .. CONFIG.roles_table .. " ur JOIN " .. CONFIG.perms_table .. " rp ON rp.role = ur.role " ..
    "WHERE ur.user_name = '" .. esc(user) .. "' AND rp.table_name = '" .. esc(tbl) .. "' AND rp." .. col .. " = true")
  return (q(r, 1, 'n') or 0) > 0
end

local function catalog_names()
  local r = _duckdb_query(
    "SELECT table_name FROM duckdb_tables() WHERE table_schema NOT IN ('information_schema','pg_catalog','temp','duckdb_catalog') " ..
    "UNION SELECT table_name FROM duckdb_views() WHERE table_schema NOT IN ('information_schema','pg_catalog','temp','duckdb_catalog')")
  local set = {}
  for i = 1, (r and #r or 0) do
    local n = r[i]['table_name']
    if n then set[n:lower()] = true end
  end
  return set
end

local function authn(p)
  local sid = p.sid or ''
  if sid == '' or #sid > 128 or not sid:match('^[%w%._%-/]+$') then return false end
  local rows = _duckdb_query(
    "SELECT user_name FROM " .. CONFIG.tokens_table .. " WHERE auth_token = '" .. esc(p.client_token or '') .. "'")
  local user = q(rows, 1, 'user_name')
  if not user then return false end
  _duckdb_query(
    "INSERT INTO " .. CONFIG.sessions_table .. " " ..
    "SELECT '" .. esc(sid) .. "' AS sid, '" .. esc(user) .. "' AS user_name " ..
    "WHERE NOT EXISTS (SELECT 1 FROM " .. CONFIG.sessions_table .. " WHERE sid = '" .. esc(sid) .. "')")
  return true
end

local function authz(p)
  local query = p.q or ''
  local up = string.upper(query)
  up = up:gsub('^%s+', ''):gsub('%s+$', '')
  if up == '' then return false end

  -- 0) quack client ATTACH handshake catalog discovery (exact shapes) → allow.
  -- Without this the v3 default-deny kills the client's own schema listing
  -- (information_schema.schemata 2-col + duckdb_tables UNION duckdb_views)
  -- and every ATTACH fails with Authorization failed. (backport of the
  -- rbac_mimic.lua fix 1cd8632 — applies to any quack client, LAN direct
  -- or quackhole tunnel.)
  local hs1 = up:find("^SELECT CATALOG_NAME, SCHEMA_NAME") and up:find("INFORMATION_SCHEMA%.SCHEMATA")
  -- hs2 covers both client generations: v1.x sends "SELECT schema_name, sql",
  -- v2.x sends "SELECT schema_oid, sql" (same tables/views UNION ALL shape).
  local hs2 = up:find("^SELECT SCHEMA") and up:find(", SQL") and up:find("DUCKDB_TABLES") and up:find("DUCKDB_VIEWS") and up:find("UNION ALL")
  -- DuckDB v2.x clients ATTACH with a WITH RECURSIVE schema_tree probe instead:
  -- duckdb_schemas() tree walk + current_database(), reading no user tables.
  local hs3 = up:find("^WITH RECURSIVE SCHEMA_TREE") and up:find("DUCKDB_SCHEMAS%(%)" ) and up:find("CURRENT_DATABASE%(%)" )
  -- v2.x clients also wrap the ATTACH probe in a transaction: bare
  -- BEGIN TRANSACTION / ROLLBACK / COMMIT (exact match, no payload).
  -- Safe: these carry no data; every DML still passes through authz
  -- statement-by-statement inside the transaction.
  if up == "BEGIN TRANSACTION" or up == "ROLLBACK" or up == "COMMIT" then return true end
  if hs1 or hs2 or hs3 then return true end

  for _, bt in ipairs(BLOCKED_TOKENS) do
    if text_has(bt.t, up, bt.prefix) then
      return false
    end
  end
  for _, cb in ipairs(CATALOG_BLOCK) do
    if text_has(cb, up) then return false end
  end

  local kind = classify(up)
  if kind == 'unknown' then return false end

  if kind == 'read' then
    for _, kw in ipairs(MID_WRITE_KWS) do
      if text_has(kw, up) then return false end
    end
    if up:find('^EXPLAIN') and (text_has('ANALYZE', up) or text_has('INSERT', up) or text_has('UPDATE', up)
        or text_has('DELETE', up) or text_has('MERGE', up) or text_has('CREATE', up) or text_has('DROP', up)) then
      return false
    end
    if CONFIG.strict_write and up:find('^WITH') then
      for _, kw in ipairs(MID_WRITE_KWS) do
        if text_has(kw, up) then return false end
      end
    end
  end

  local user = resolve_user(p.sid)
  if not user then return false end

  local need_write = (kind == 'write')
  if need_write and not CONFIG.allow_write then return false end

  for name in pairs(META_TABLES) do
    if text_has(name:upper(), up) then return false end
  end

  local cat = catalog_names()
  for bare in pairs(cat) do
    if text_has(bare:upper(), up) then
      if not user_has_perm(user, bare, need_write) then return false end
    end
  end
  for _, tbl in ipairs(CONFIG.protected) do
    if not cat[tbl] and text_has(tbl:upper(), up) then
      if not user_has_perm(user, tbl, need_write) then return false end
    end
  end

  if CONFIG.audit_table then
    _duckdb_query("INSERT INTO " .. CONFIG.audit_table ..
      " VALUES ('" .. esc(p.sid or '') .. "', '" .. esc(user) .. "', '" .. esc(query) .. "', CURRENT_TIMESTAMP)")
  end
  return true
end

local function grant(p)
  local role, tbl = (p.role or ''):lower(), (p.tbl or ''):lower()
  if role == '' or tbl == '' then return 'error: role/tbl required' end
  if META_TABLES[tbl] then return 'error: cannot grant RBAC metadata table ' .. tbl end
  local cat = catalog_names()
  if not cat[tbl] then return 'error: table ' .. tbl .. ' not found' end
  local ok, err = pcall(function()
    _duckdb_query("INSERT OR REPLACE INTO " .. CONFIG.perms_table ..
      " VALUES ('" .. esc(role) .. "', '" .. esc(tbl) .. "', " ..
      (p.can_select and 'true' or 'false') .. ", " .. (p.can_write and 'true' or 'false') .. ")")
  end)
  return ok and 'ok' or ('error: ' .. tostring(err))
end

local function setup()
  local ddl = {
    "CREATE TABLE IF NOT EXISTS " .. CONFIG.tokens_table .. " (auth_token VARCHAR PRIMARY KEY, user_name VARCHAR)",
    "CREATE TABLE IF NOT EXISTS " .. CONFIG.sessions_table .. " (sid VARCHAR PRIMARY KEY, user_name VARCHAR)",
    "CREATE TABLE IF NOT EXISTS " .. CONFIG.roles_table .. " (user_name VARCHAR, role VARCHAR)",
    "CREATE TABLE IF NOT EXISTS " .. CONFIG.perms_table .. " (role VARCHAR, table_name VARCHAR, can_select BOOLEAN, can_write BOOLEAN, PRIMARY KEY(role, table_name))",
  }
  for _, s in ipairs(ddl) do
    local ok, err = pcall(function() _duckdb_query(s) end)
    if not ok then return 'error: ' .. tostring(err) end
  end
  return 'ok'
end

return function(p)
  if not p or not p.op then return 'error: need op' end
  if p.op == 'authn' then return authn(p) end
  if p.op == 'authz' then return authz(p) end
  if p.op == 'grant' then return grant(p) end
  if p.op == 'setup' then return setup() end
  if p.op == 'tables' then
    return table.concat(CONFIG.protected, ',')
  end
  if p.op == 'status' then
    return 'protected=' .. table.concat(CONFIG.protected, ',') .. ';allow_write=' .. tostring(CONFIG.allow_write) ..
           ';strict_write=' .. tostring(CONFIG.strict_write) .. ';audit=' .. tostring(CONFIG.audit_table or 'off')
  end
  return 'error: unknown op ' .. tostring(p.op)
end
