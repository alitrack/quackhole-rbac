-- @lib: rbac
-- @category: security
-- @desc: Quack RBAC 策略引擎 v3——token 认证 + 连接会话记录 + 全目录 default-deny 表级授权 + 函数/关键字黑名单加固，
--        挂 quack_authentication_function / quack_authorization_function 钩子（普通模式，需 _duckdb_query）
-- @source: original（duckdb-luajit 系列）
-- @requires: _duckdb_query（普通模式；trusted 沙箱下不可用）
-- Role-Based Access Control policy engine for DuckDB Quack (LuaJIT 5.1), v3.
--
-- 定位：Quack 是强制点（每条查询 PREPARE 前跑 authorization 钩子），本库是策略引擎。
--
-- v3 安全模型（相对 v2 的修复，全部经 2026-10-13 实测验证矩阵覆盖）：
--   1) 表匹配改为【大小写不敏感 + 词边界】：DuckDB 标识符大小写不敏感，v2 对小写子串
--      的匹配可被大写引用绕过（SELECT * FROM SECRET_DATA）——v3 对原始查询大写后匹配。
--   2) 全目录 default-deny：不再只查 protected 清单（v2 的"未列名表零授权可读"漏洞），
--      authz 每次动态枚举 duckdb_tables()/duckdb_views()，凡查询引用了任一现存表/视图
--      就必须有 can_select 授权；不存在任何授权的表一律拒绝。
--   3) RBAC 元数据表(quack_tokens/quack_sessions/user_roles/role_perms)恒拒：
--      任何角色都不可读写（防 token dump / 自授角色），grant() 也拒绝授予这些表。
--   4) 系统目录(information_schema/pg_catalog/duckdb_catalog)恒拒（防目录列举）。
--   5) 函数/关键字黑名单：LUAJIT_S / LUAJIT_MODULE / INSTALL / LOAD / ATTACH / DETACH /
--      PRAGMA / SET GLOBAL / DUCKDB_ 等出现在查询文本任意位置（大小写不敏感）一律拒绝——
--      堵住"带副作用的 SELECT"（SELECT luajit_s('rbac',{op:'grant'...})）以及
--      远程 INSTALL/LOAD/ATTACH 换函数/换库的路径。grant/setup/authn 操作因此
--      在远程 SQL 下不可达，只能由服务器本地会话执行。
--   6) 语句类型仍为前缀分类（非解析器），但叠加：a) 读取语句文本中再出现强写关键字
--      （INSERT/UPDATE/DELETE/MERGE/CREATE/DROP/...）一律拒绝（堵 "SELECT 1; INSERT ..."
--      堆叠语句）；b) EXPLAIN 后含写关键字/ANALYZE 一律拒绝（堵 EXPLAIN ANALYZE INSERT）；
--      c) strict_write 时 WITH 开头且文本含写关键字才拒绝（合法 CTE 读不再被误杀，
--      "WITH x AS (SELECT 1) INSERT ..." 仍被拒）。
-- 仍为已知残留（文档已声明）：子串/词边界匹配非解析器——字符串字面量或注释中含表名/
-- 写关键字会造成"错杀"（误拒，非绕过）；_duckdb_query 在 luajit_s 内部可用，若黑名单
-- 出现未知新函数名则需同步扩充。生产信任边界仍需 per-user ticket + 审计 + 自建 relay。
--
-- 表模型（管理员在服务器会话执行 luajit_s('rbac', {op:'setup'}) 一次）：
--   quack_tokens (auth_token PK, user_name)   -- token→用户
--   quack_sessions (sid PK, user_name)        -- 连接→用户（authn 钩子写入，不覆盖已有映射）
--   user_roles (user_name, role)              -- 用户→角色
--   role_perms (role, table_name, can_select, can_write, PK(role,table_name))
--
-- 挂钩（服务器会话，LOAD luajit + compile 本库之后）：
--   CREATE MACRO rbac_authn(sid, ct, st) AS (luajit_s('rbac', {op:'authn', sid:sid, client_token:ct, server_token:st})::BOOLEAN);
--   CREATE MACRO rbac_authz(sid, q)    AS (luajit_s('rbac', {op:'authz', sid:sid, q:q})::BOOLEAN);
--   SET GLOBAL quack_authentication_function = 'rbac_authn';
--   SET GLOBAL quack_authorization_function  = 'rbac_authz';
--
-- 调用（luajit_s('rbac', {op:...})）：
--   authn  → BOOLEAN（查 token 表 + 写会话表；仅本地/钩子上下文可触达，远程 SQL 被 authz 黑名单拒绝）
--   authz  → BOOLEAN（default-deny 全目录 + 角色表级权限 + 元数据恒拒）
--   grant  → 管理员专用 {op:'grant', role, tbl, can_select, can_write}（拒绝元数据表/不存在表；仅服务器本地执行）
--   setup  → 管理员专用：建 4 张 RBAC 表（仅服务器本地执行）
--   tables → 返回 protected 清单（逗号分隔），供 server.py 做动态授权
--   status → 配置快照（调试用）

local CONFIG = {
  tokens_table   = 'quack_tokens',
  sessions_table = 'quack_sessions',
  roles_table    = 'user_roles',
  perms_table    = 'role_perms',
  -- 域受控表清单（全目录 default-deny 之下，此清单是文档化的"业务表"集合；
  -- server.py 用它生成 researcher/viewer 的动态授权）
  protected      = {
    -- 12 基础临床表
    'admissions', 'patients', 'diagnoses_icd', 'procedures_icd',
    'd_icd_diagnoses', 'd_icd_procedures', 'drgcodes', 'services',
    'transfers', 'icustays', 'd_items', 'charlson',
    -- 6 模板语义层
    'mortality', 'demographics', 'icd_diagnoses', 'prognosis',
    'comorbidities', 'study_comorbidity_flags',
    -- 4 本体层 (SNOMED/LOINC/RxNorm)
    's_mimic_icd_map', 's_lab_loinc_map', 's_rxnorm_ndc_map', 's_concept_std',
    -- 1 golden 校验
    'template_golden',
  },
  allow_write    = false,  -- true = 放行写语句并按 can_write 细粒度授权；false = 一切写语句拒绝（推荐）
  strict_write   = true,   -- true = WITH 开头且含写关键字一律拒绝（合法 CTE 读放行）
  audit_table    = nil,    -- 设 'rbac_audit' 则 authz 每次决策记审计（每查询多一次写，性能敏感慎用）
}

-- RBAC 元数据：恒拒（任何角色不可读写，grant 也不可为其授权）
local META_TABLES = {
  [CONFIG.tokens_table]   = true,
  [CONFIG.sessions_table] = true,
  [CONFIG.roles_table]    = true,
  [CONFIG.perms_table]    = true,
}
-- 系统目录：恒拒（防目录/元数据列举）
local CATALOG_BLOCK = { 'INFORMATION_SCHEMA', 'PG_CATALOG', 'DUCKDB_CATALOG' }
-- 远程查询文本中任意位置出现即拒绝（大小写不敏感）。
-- 以 '_'/' ' 结尾的按前缀匹配（DUCKDB_ 后跟函数名；LOAD 后跟空格）
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
-- 强写关键字：出现在"读取"语句文本任意位置即拒绝（堵堆叠语句/副作用）
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

-- 词边界子串匹配：needle（大写）出现在 hay（大写）中，且 needle 前一位是
-- 行首或非标识符字符；prefix=true 时不检查后界（用于 'DUCKDB_'、'LOAD ' 类前缀）
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

-- 现存用户表/视图（bare 名 + schema.name 两种形态，小写）
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
  -- sid 形态校验：非空、限长、仅安全字符（防垃圾会话写入/注入）
  if sid == '' or #sid > 128 or not sid:match('^[%w%._%-/]+$') then return false end
  local rows = _duckdb_query(
    "SELECT user_name FROM " .. CONFIG.tokens_table .. " WHERE auth_token = '" .. esc(p.client_token or '') .. "'")
  local user = q(rows, 1, 'user_name')
  if not user then return false end
  -- 已有会话映射不被覆盖（防以新 token 顶掉受害者 sid）
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
  -- Without this the v3 default-deny kills the client own schema listing
  -- (information_schema.schemata 2-col + duckdb_tables UNION duckdb_views)
  -- and every ATTACH fails with Authorization failed.
  local hs1 = up:find("^SELECT CATALOG_NAME, SCHEMA_NAME") and up:find("INFORMATION_SCHEMA%.SCHEMATA")
  local hs2 = up:find("^SELECT SCHEMA_NAME, SQL") and up:find("DUCKDB_TABLES") and up:find("DUCKDB_VIEWS") and up:find("UNION ALL")
  if hs1 or hs2 then return true end

  -- 1) 函数/关键字黑名单：任意位置出现即拒（大小写不敏感）
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

  -- 2) 读取语句文本中再出现强写关键字 → 拒（堵堆叠语句 / "SELECT ..; INSERT .."）
  if kind == 'read' then
    for _, kw in ipairs(MID_WRITE_KWS) do
      if text_has(kw, up) then return false end
    end
    -- EXPLAIN 含写关键字或 ANALYZE → 拒（堵 EXPLAIN ANALYZE <write> 执行副作用）
    if up:find('^EXPLAIN') and (text_has('ANALYZE', up) or text_has('INSERT', up) or text_has('UPDATE', up)
        or text_has('DELETE', up) or text_has('MERGE', up) or text_has('CREATE', up) or text_has('DROP', up)) then
      return false
    end
    -- 3) strict_write：WITH 开头且文本含写关键字 → 拒（合法 CTE 读放行）
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

  -- 4) RBAC 元数据恒拒（防 token dump / 权限表读取）
  for name in pairs(META_TABLES) do
    if text_has(name:upper(), up) then return false end
  end

  -- 5) 全目录 default-deny：查询引用的每个现存表/视图都必须有授权
  local cat = catalog_names()
  for bare in pairs(cat) do
    if text_has(bare:upper(), up) then
      if not user_has_perm(user, bare, need_write) then return false end
    end
  end
  -- 防御：protected 清单中（可能未建表的）名称同样检查
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

-- 管理员操作：仅服务器本地会话执行。远程 SQL 调用 luajit_s 会被 authz 黑名单拒绝。
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
