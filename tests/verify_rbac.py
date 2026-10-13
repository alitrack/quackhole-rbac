#!/usr/bin/env python3
"""RBAC policy-engine regression suite for quackhole-rbac (v3).

Run (from the repo root, with a venv that has duckdb>=1.5.5 and network for the
luajit/quack extension install):

    uv venv --python 3.13 .venv && uv pip install -p .venv 'duckdb>=1.5.5'
    .venv/bin/python tests/verify_rbac.py

What it verifies, IN-PROCESS on a local DuckDB (no P2P transport, no network):
  1. authz decision matrix — every v2 bypass vector (case bypass, default-deny,
     RBAC-metadata dump, luajit_s grant/setup shell, stacked writes, EXPLAIN
     ANALYZE, WITH..INSERT, INSTALL/LOAD/ATTACH, macro takeover, SET GLOBAL)
     is denied; legitimate reads (incl. CTE) are allowed.
  2. the server's EXACT hook chain — the same rbac_authn / rbac_authz macros with
     ::BOOLEAN that server.py registers via SET GLOBAL — driven the way the quack
     server-side handler drives them (authn: token->user+session; authz: policy),
     plus session no-overwrite and unknown-token rejection.
  3. server.py reseed_identities idempotency — running it twice on a populated DB
     must not raise a PK violation (v2 crashed here on the 2nd run).

The P2P transport (quackhole/iroh) is deliberately NOT exercised here: a same-host
server+client share one iroh identity and iroh refuses "Connecting to ourself".
To verify the full tunnel+client path, run server.py on host A and
`client/client.py --ticket ... --matrix` on host B.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "server"))
os.chdir(ROOT)  # relative lua path + fresh in-memory db

import duckdb  # noqa: E402
import server  # noqa: E402  (for reseed_identities)

SAMPLE_LUA = os.path.join(ROOT, "server", "rbac_sample.lua")


def parse_bool(raw):
    return bool(raw) if isinstance(raw, bool) else (raw == "true")


def build_engine(con):
    con.execute("INSTALL luajit FROM community; LOAD luajit;")
    with open(SAMPLE_LUA, encoding="utf-8-sig") as f:
        src = f.read()
    con.execute("SELECT * FROM luajit_module(mode := 'compile', sql_name := 'rbac', source := $1)", [src])
    con.execute("SELECT luajit_s('rbac', {op:'setup'})")


def seed(con):
    con.execute("CREATE TABLE secret_data(id INT, name VARCHAR); INSERT INTO secret_data VALUES (1,'classified')")
    con.execute("CREATE TABLE public_data(id INT, name VARCHAR); INSERT INTO public_data VALUES (1,'open')")
    con.execute("CREATE TABLE other_data(id INT, name VARCHAR); INSERT INTO other_data VALUES (1,'other')")
    con.execute("INSERT INTO quack_tokens VALUES ('alice-tok','alice'),('bob-tok','bob'),('tunnel','tunnel')")
    con.execute("INSERT INTO user_roles VALUES ('alice','analyst'),('bob','viewer'),('tunnel','tunnel_role')")
    con.execute("INSERT INTO role_perms VALUES "
                "('analyst','secret_data',true,false),('analyst','public_data',true,false),('analyst','other_data',true,false),"
                "('viewer','public_data',true,false),"
                "('tunnel_role','public_data',true,false)")
    con.execute("INSERT INTO quack_sessions VALUES ('sid-alice','alice'),('sid-bob','bob'),('sid-tunnel','tunnel')")


# (sid, sql, expected, label) — the v3 authz decision matrix
AUTHZ_CASES = [
    ("sid-alice", "SELECT * FROM secret_data", True,  "analyst read secret (lc)"),
    ("sid-alice", "SELECT * FROM SECRET_DATA", True,  "analyst read secret (UPPER) — v2 case-bypass now closed"),
    ("sid-alice", 'SELECT * FROM "secret_data"', True, "analyst read secret (quoted)"),
    ("sid-alice", "SELECT * FROM r.secret_data", True, "analyst read secret (schema-qualified)"),
    ("sid-alice", "SELECT * FROM other_data", True,   "analyst read other_data (granted)"),
    ("sid-bob",   "SELECT * FROM public_data", True,  "viewer read public (granted)"),
    ("sid-bob",   "SELECT * FROM PUBLIC_DATA", True,  "viewer read public (UPPER, granted) — case-insensitive now correct"),
    ("sid-bob",   "SELECT * FROM secret_data", False, "viewer read secret -> DENY (no grant)"),
    ("sid-bob",   "SELECT * FROM SECRET_DATA", False, "viewer read SECRET (UPPER) -> DENY (closed: not a bypass)"),
    ("sid-bob",   "SELECT * FROM other_data", False,  "viewer read other -> DENY (default-deny, ungranted)"),
    ("sid-alice", "SELECT 1 FROM duckdb_settings()", False, "system fn -> DENY (blocked DUCKDB_ token)"),
    ("sid-bob",   "SELECT * FROM information_schema.tables", False, "information_schema -> DENY (catalog)"),
    ("sid-alice", "SELECT * FROM quack_tokens", False, "dump quack_tokens -> DENY (RBAC meta)"),
    ("sid-alice", "SELECT * FROM QUACK_TOKENS", False, "dump QUACK_TOKENS (UPPER) -> DENY (meta, case-closed)"),
    ("sid-bob",   "SELECT * FROM user_roles", False, "read user_roles -> DENY (meta)"),
    ("sid-bob",   "SELECT * FROM role_perms", False, "read role_perms -> DENY (meta)"),
    ("sid-bob",   "INSERT INTO user_roles VALUES ('bob','analyst')", False, "self-grant role -> DENY"),
    ("sid-bob",   "INSERT INTO public_data VALUES (9,'x')", False, "write -> DENY (allow_write=false)"),
    ("sid-bob",   "UPDATE role_perms SET can_select=true", False, "tamper role_perms -> DENY"),
    ("sid-bob",   "DROP TABLE secret_data", False, "drop -> DENY"),
    ("sid-bob",   "SELECT luajit_s('rbac', {op:'grant', role:'viewer', tbl:'secret_data', can_select:true})", False, "luajit_s grant shell -> DENY (blocked fn)"),
    ("sid-bob",   "SELECT luajit_s('rbac', {op:'setup'})", False, "luajit_s setup -> DENY (blocked fn)"),
    ("sid-bob",   "SELECT * FROM secret_data; INSERT INTO user_roles VALUES('bob','analyst')", False, "stacked write -> DENY (mid-text INSERT)"),
    ("sid-bob",   "EXPLAIN ANALYZE INSERT INTO user_roles VALUES('bob','analyst')", False, "EXPLAIN ANALYZE write -> DENY"),
    ("sid-bob",   "WITH x AS (SELECT 1) INSERT INTO user_roles SELECT 'bob','analyst'", False, "WITH..INSERT -> DENY (strict_write)"),
    ("sid-alice", "WITH x AS (SELECT * FROM public_data) SELECT * FROM x", True,  "legit CTE read -> PASS (not falsely denied)"),
    ("sid-alice", "WITH x AS (SELECT * FROM secret_data) SELECT * FROM x", True, "legit CTE read secret -> PASS (granted)"),
    ("sid-bob",   "CREATE OR REPLACE MACRO rbac_authz(sid, query) AS (true)", False, "macro takeover -> DENY"),
    ("sid-bob",   "SET GLOBAL quack_authorization_function = 'quack_nop_authorization'", False, "SET GLOBAL swap -> DENY (blocked)"),
    ("sid-bob",   "INSTALL quackhole FROM community", False, "INSTALL -> DENY (blocked)"),
    ("sid-bob",   "LOAD luajit", False, "LOAD -> DENY (blocked)"),
    ("sid-bob",   "ATTACH 'evil.duckdb' AS e", False, "ATTACH -> DENY (blocked)"),
    ("sid-bob",   "SELECT 'secret_data' AS label", False, "ungranted user: literal w/ table name -> DENY (documented false-denial, no read)"),
]


def check(label, cond, extra=""):
    print(f"[{'OK ' if cond else 'BAD'}] {label}{(' — ' + extra) if extra and not cond else ''}")
    return bool(cond)


def main():
    con = duckdb.connect()
    build_engine(con)
    seed(con)
    total, passed = 0, 0

    def authz(sid, sql):
        raw = con.execute("SELECT luajit_s('rbac', {op:'authz', sid:?, q:?})", [sid, sql]).fetchone()[0]
        return parse_bool(raw)

    print("=== 1) authz decision matrix (direct engine) ===")
    for sid, sql, exp, label in AUTHZ_CASES:
        got = authz(sid, sql)
        total += 1
        if check(label, got == exp, f"want={exp} got={got} sql={sql[:80]}"):
            passed += 1

    print("\n=== 2) server hook chain (server-identical macros + ::BOOLEAN + SET GLOBAL) ===")
    con.execute("INSTALL quack; LOAD quack;")
    con.execute("CREATE MACRO rbac_authn(sid, ct, st) AS "
                "(luajit_s('rbac', {op:'authn', sid:sid, client_token:ct, server_token:st})::BOOLEAN)")
    con.execute("CREATE MACRO rbac_authz(sid, query) AS "
                "(luajit_s('rbac', {op:'authz', sid:sid, q:query})::BOOLEAN)")
    con.execute("SET GLOBAL quack_authentication_function = 'rbac_authn'")
    con.execute("SET GLOBAL quack_authorization_function = 'rbac_authz'")
    rows = dict(con.execute("SELECT name,value FROM duckdb_settings() WHERE name IN "
                            "('quack_authentication_function','quack_authorization_function')").fetchall())
    if check("hooks registered (exact)", rows == {
            'quack_authentication_function': 'rbac_authn', 'quack_authorization_function': 'rbac_authz'}, str(rows)):
        passed += 1
    total += 1

    def authn(sid, ctok):
        return bool(con.execute("SELECT rbac_authn(?, ?, 'srv')", [sid, ctok]).fetchone()[0])
    def authz_macro(sid, sql):
        return bool(con.execute("SELECT rbac_authz(?, ?)", [sid, sql]).fetchone()[0])

    authn("sid-alice", "alice-tok"); authn("sid-bob", "bob-tok"); authn("sid-tunnel", "tunnel-tok")
    hook_cases = [
        ("sid-alice", "SELECT * FROM secret_data", True,  "alice(analyst) read secret"),
        ("sid-bob",   "SELECT * FROM public_data", True,  "bob(viewer) read public"),
        ("sid-bob",   "SELECT * FROM secret_data", False, "bob read secret -> DENY"),
        ("sid-bob",   "SELECT * FROM QUACK_TOKENS", False, "bob dump QUACK_TOKENS -> DENY (meta)"),
        ("sid-bob",   "SELECT luajit_s('rbac', {op:'grant', role:'viewer', tbl:'secret_data', can_select:true})", False, "luajit_s grant -> DENY"),
        ("sid-bob",   "INSERT INTO user_roles VALUES ('bob','analyst')", False, "self-grant -> DENY"),
        ("sid-evil",  "SELECT * FROM public_data", False, "unauthenticated sid -> DENY (no session)"),
    ]
    for sid, sql, exp, label in hook_cases:
        got = authz_macro(sid, sql)
        total += 1
        if check(label, got == exp, f"want={exp} got={got}"):
            passed += 1

    # session semantics: no overwrite of an existing sid; unknown token rejected
    authn("sid-new", "bob-tok")
    authn("sid-new", "alice-tok")
    sess = dict(con.execute("SELECT sid, user_name FROM quack_sessions").fetchall())
    total += 1
    if check("session no-overwrite (sid-new stays 'bob')", sess.get("sid-new") == "bob", f"got={sess.get('sid-new')}"):
        passed += 1
    total += 1
    if check("unknown token -> authn False", authn("sid-x", "nope") is False):
        passed += 1

    con.close()

    print("\n=== 3) reseed_identities idempotency (server.py) ===")
    import tempfile
    dbfile = os.path.join(tempfile.gettempdir(), "qh_rbac_reseed_test.duckdb")
    if os.path.exists(dbfile):
        os.remove(dbfile)
    c2 = duckdb.connect(dbfile)
    build_engine(c2)
    seed(c2)
    server.reseed_identities(c2, "sample", "test-tunnel-tok")
    total += 1
    if check("reseed run #1 (populated db) does not raise PK", True):
        passed += 1
    try:
        server.reseed_identities(c2, "sample", "test-tunnel-tok")
        ok = True
    except Exception as e:
        ok = False
        print("    reseed #2 raised:", str(e).splitlines()[0][:120])
    total += 1
    if check("reseed run #2 idempotent (v2 crashed here)", ok):
        passed += 1
    toks = c2.execute("SELECT count(*) FROM quack_tokens").fetchone()[0]
    roles = c2.execute("SELECT count(*) FROM user_roles").fetchone()[0]
    c2.close()
    total += 1
    if check(f"stable counts after 2x reseed (tokens=3 roles=3)", toks == 3 and roles == 3, f"tokens={toks} roles={roles}"):
        passed += 1
    if os.path.exists(dbfile):
        os.remove(dbfile)

    print(f"\n{'='*50}\nRESULT: {passed}/{total} checks passed, {total-passed} failed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
