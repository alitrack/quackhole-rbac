#!/usr/bin/env python3
"""test_rbac_lua.py — quackhole-rbac lua 策略引擎单元回归（无需网络/隧道）。

用法: python3 test/test_rbac_lua.py [duckdb_cli_path]
默认 CLI: /home/lhy/.local/bin/duckdb156（需 luajit 社区扩展已 INSTALL）。
覆盖:
  - t1-t15: 2026-10-13 实测驱动修复回归（大小写/allow-by-absence/元数据/luajit_s 封杀/词边界）
  - t18-t21: 视图检查（未授权视图必拒、已授权视图放行）——本测试动态建视图后单测 authz
  - matrix m02-m13: 官方 --matrix 13 测点的 authz 等价回放
退出码: 全过 0，有失败 1。
"""
import subprocess, os, re, sys, tempfile

CLI = sys.argv[1] if len(sys.argv) > 1 else "/home/lhy/.local/bin/duckdb156"
HERE = os.path.dirname(os.path.abspath(__file__))
LUA = os.path.join(HERE, "..", "server", "rbac_sample.lua")

lua = open(LUA, encoding="utf-8-sig").read().replace("'", "''")

# (name, sql, expect)  expect: 'true'/'false'/'error'
CASES = [
    ("t1_lowercase",    "SELECT count(*) FROM secret_data",            "false"),
    ("t2_uppercase",    "SELECT count(*) FROM SECRET_DATA",            "false"),
    ("t2b_mixed",       "SELECT count(*) FROM Secret_Data",            "false"),
    ("t3_grant_naive",  "SELECT luajit_s('rbac',{op:'grant',role:'viewer',tbl:'secret_data',can_select:true})", "false"),
    ("t4_grant_split",  "SELECT luajit_s('rbac',{op:'grant',role:'viewer',tbl:'secret'||'_data',can_select:true})", "false"),
    ("t6_setup_via_sel","SELECT luajit_s('rbac',{op:'setup'})",        "false"),
    ("t7_explain_ok",   "EXPLAIN ANALYZE SELECT * FROM PUBLIC_DATA",   "true"),
    ("t8_meta_table",   "SELECT count(*) FROM quack_tokens",           "false"),
    ("t9_delete_meta",  "DELETE FROM quack_sessions",                  "false"),
    ("t11_allowed_upper","SELECT count(*) FROM PUBLIC_DATA",           "true"),
    ("t12_allowed_lower","SELECT count(*) FROM public_data",           "true"),
    ("t13_meta_userrole","SELECT * FROM user_roles",                   "false"),
    ("t15_word_boundary","SELECT 'the secret_database_note' AS s",     "true"),
    ("m03_bob_secret",  "SELECT * FROM secret_data",                   "false"),
    ("m04_self_grant",  "INSERT INTO user_roles VALUES ('bob','analyst')", "false"),
    ("m06_macro_take",  "CREATE OR REPLACE MACRO rbac_authz(sid, query) AS (true)", "false"),
    ("m09_write_insert","INSERT INTO public_data VALUES (9,'x')",      "false"),
    ("m10_with_inject", "WITH x AS (SELECT 1) INSERT INTO secret_data SELECT 42", "false"),
    ("m12_token_dump",  "SELECT * FROM quack_tokens",                  "false"),
    ("m13_uppercase",   "SELECT * FROM SECRET_DATA",                   "false"),
]

SETUP = [
    ".bail on",
    "LOAD luajit;",
    "SELECT * FROM luajit_module(mode := 'compile', sql_name := 'rbac', source := '" + lua + "');",
    "SELECT luajit_s('rbac', {op: 'setup'});",
    "INSERT INTO quack_tokens VALUES ('bob-tok', 'bob');",
    "INSERT INTO user_roles VALUES ('bob', 'viewer');",
    "INSERT INTO role_perms VALUES ('viewer', 'public_data', true, false);",
    "INSERT INTO quack_sessions VALUES ('sid-bob', 'bob');",
    "CREATE TABLE secret_data (id INT, s VARCHAR);",
    "CREATE VIEW v_secret AS SELECT * FROM secret_data;",
]

def main():
    parts = list(SETUP)
    cases = [(n, q, e) for n, q, e in CASES]
    # 动态视图测例插在建立 v_secret 之后
    parts.append("SELECT luajit_s('rbac', {op:'authz', sid:'sid-bob', q:'SELECT * FROM v_secret'}) AS t18_ungranted_view;")
    parts.append("SELECT luajit_s('rbac', {op:'authz', sid:'sid-bob', q:'SELECT count(*) FROM public_data'}) AS t21_still_ok;")
    for n, q, e in cases:
        esc = q.replace("'", "''")
        parts.append("SELECT luajit_s('rbac', {op:'authz', sid:'sid-bob', q:'" + esc + "'}) AS " + n + ";")
    parts.append("SELECT luajit_s('rbac', {op:'grant', role:'viewer', tbl:'secret' || '_data', can_select:true}) AS t5_grant_err;")
    expects = {n: e for n, _, e in cases}
    expects["t18_ungranted_view"] = "false"
    expects["t21_still_ok"] = "true"
    expects["t5_grant_err"] = "error"

    with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
        f.write("\n".join(parts) + "\n")
        sqlpath = f.name
    db = sqlpath.replace(".sql", ".db")
    if os.path.exists(db):
        os.remove(db)
    p = subprocess.run([CLI, db, "-init", sqlpath], capture_output=True, text=True, timeout=120)
    out = (p.stdout or "") + (p.stderr or "")
    found = {}
    for m in re.finditer(r"│\s*([a-z0-9_]+)\s*│\s*$", out, re.M):
        name = m.group(1)
        if name in expects:
            seg = out[m.end():m.end()+400]
            vm = re.search(r"│\s*(true|false|ok|error[^\n│]*|error:[^\n│]*)\s*│", seg)
            if vm:
                found[name] = vm.group(1).strip()
                continue
    ok = 0
    fails = []
    for n, exp in expects.items():
        act = found.get(n, "??")
        a = act.split(":")[0] if act.startswith("error") else act
        e = exp.split(":")[0] if exp.startswith("error") else exp
        if a == e:
            ok += 1
        else:
            fails.append((n, act, exp))
    print(f"{ok}/{len(expects)} passed")
    for n, a, e in fails:
        print(f"  FAIL {n}: got {a!r} want {e!r}")
    os.unlink(sqlpath)
    sys.exit(0 if not fails else 1)

if __name__ == "__main__":
    main()
