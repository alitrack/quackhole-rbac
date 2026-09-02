#!/usr/bin/env python3
"""quackhole-rbac server: luajit RBAC policy + quack authn/authz hooks + quackhole P2P tunnel.

Runs the RBAC-over-quackhole server on top of any DuckDB file. External clients
attach via the printed quackhole ticket; every query is enforced server-side by
the luajit rbac.lua policy engine (role -> table-level SELECT, write-denied).

Usage:
    python server.py [--db PATH] [--lua PATH] [--ticket PATH] [--token TOK] [--sample]
    --db       DuckDB file to serve (default: env QUACKHOLE_DB or ./rbac.duckdb)
    --lua      rbac policy lua (default: ./rbac_mimic.lua next to this script)
    --ticket   where to write the ticket (default: /tmp/qh_rbac_ticket.txt)
    --token    tunnel shared token (default: env QUACKHOLE_TOKEN or 'qh-tok')
    --sample   create sample secret_data/public_data tables (for demos/tests)

Environment:
    QUACKHOLE_DB, QUACKHOLE_TOKEN  — same as --db / --token

Roles seeded (edit below or pre-provision tables in your DB):
    quack_tokens(auth_token PK, user_name)   — token -> user
    user_roles(user_name, role)              — user -> role
    role_perms(role, table_name, can_select, can_write) — role -> table perms
"""
import argparse, os, re, sys, tempfile, time

try:
    import duckdb
except ImportError:
    sys.exit("duckdb not installed: uv venv && uv pip install duckdb")

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=os.environ.get("QUACKHOLE_DB", "./rbac.duckdb"))
    p.add_argument("--lua", default=os.path.join(HERE, "rbac_mimic.lua"))
    p.add_argument("--ticket", default=os.path.join(tempfile.gettempdir(), "qh_rbac_ticket.txt"))
    p.add_argument("--token", default=os.environ.get("QUACKHOLE_TOKEN", "qh-tok"))
    p.add_argument("--port", type=int, default=9494,
                   help="quack port for quackhole to auto-serve (default 9494; "
                        "use another port if 9494 is taken, e.g. by WSL's localhost relay)")
    p.add_argument("--sample", action="store_true")
    p.add_argument("--luajit-so", default=None,
                   help="path to a locally-built luajit.duckdb_extension (unsigned); "
                        "default: install luajit FROM community")
    return p.parse_args()


def connect(db, luajit_so):
    cfg = {"allow_unsigned_extensions": "true"} if luajit_so else {}
    con = duckdb.connect(db, config=cfg)
    if luajit_so:
        con.execute(f"LOAD '{luajit_so}'")
    else:
        con.execute("INSTALL luajit FROM community; LOAD luajit;")
    return con


def main():
    args = parse_args()
    if args.sample and os.path.exists(args.db):
        os.remove(args.db)
    con = connect(args.db, args.luajit_so)

    # sample mode: use the sample policy (secret_data/public_data) and seed them
    lua = args.lua
    if args.sample:
        lua = os.path.join(HERE, "rbac_sample.lua")
        con.execute("CREATE TABLE secret_data (id INTEGER, name VARCHAR)")
        con.execute("INSERT INTO secret_data VALUES (1,'classified'),(2,'top-secret')")
        con.execute("CREATE TABLE public_data (id INTEGER, name VARCHAR)")
        con.execute("INSERT INTO public_data VALUES (1,'open'),(2,'public')")

    # --- RBAC policy engine (compile + create the 4 RBAC tables) ---
    with open(lua, "r", encoding="utf-8-sig") as f:
        lua_src = f.read()
    con.execute("SELECT * FROM luajit_module(mode := 'compile', sql_name := 'rbac', source := $1)",
                [lua_src])
    print("rbac setup:", con.execute("SELECT luajit_s('rbac', {op: 'setup'})").fetchall(), flush=True)

    # --- seed identities ---
    if args.sample:
        con.execute("INSERT INTO quack_tokens VALUES "
                    "('alice-tok','alice'),('bob-tok','bob'),(?, 'tunnel')", [args.token])
        con.execute("INSERT INTO user_roles VALUES "
                    "('alice','analyst'),('bob','viewer'),('tunnel','tunnel_role')")
        con.execute("INSERT INTO role_perms VALUES "
                    "('analyst','public_data',true,false),('analyst','secret_data',true,false),"
                    "('viewer','public_data',true,false),('viewer','secret_data',false,false),"
                    "('tunnel_role','public_data',true,false),('tunnel_role','secret_data',false,false)")
    else:
        con.execute("INSERT INTO quack_tokens VALUES "
                    "('researcher-tok','researcher'),('viewer-tok','viewer'),(?, 'tunnel')",
                    [args.token])
        con.execute("INSERT INTO user_roles VALUES "
                    "('researcher','researcher_role'),('viewer','viewer_role'),('tunnel','tunnel_role')")
        # 动态授权：从 rbac lua 的 protected 清单给 researcher_role 全表读权限，
        # viewer_role 只给 4 张本体词表(公开展示层)，tunnel_role 最小(仅 admissions 供隧道探测)
        # RBAC 元数据表(quack_*/user_*/role_*)永不授权——客户端一律不可读写
        protected_tables = re.findall(r"'(\w+)'", lua_src.split("protected")[1].split("}")[0])
        data_tables = [t for t in protected_tables
                       if not t.startswith(("quack_", "user_", "role_"))]
        perms_sql = ",".join(
            f"('researcher_role','{t}',true,false)" for t in data_tables)
        viewer_tables = [t for t in data_tables if t.startswith("s_")]
        perms_sql += "," + ",".join(
            f"('viewer_role','{t}',true,false)" for t in viewer_tables)
        perms_sql += ",('tunnel_role','admissions',true,false)"
        con.execute(f"INSERT INTO role_perms VALUES {perms_sql}")
        print(f"seeded perms: researcher={len(data_tables)} tables, "
              f"viewer={len(viewer_tables)} tables (RBAC meta excluded)", flush=True)

    # --- quack + quackhole (MUST load BEFORE SET GLOBAL hooks: settings only
    #     exist after the extension is loaded; setting them earlier is silently dropped) ---
    con.execute("INSTALL quack; LOAD quack;")
    con.execute("INSTALL quackhole FROM community; LOAD quackhole;")

    # --- quack authn/authz hooks ---
    con.execute("CREATE MACRO rbac_authn(sid, ct, st) AS "
                "(luajit_s('rbac', {op:'authn', sid:sid, client_token:ct, server_token:st})::BOOLEAN)")
    con.execute("CREATE MACRO rbac_authz(sid, query) AS "
                "(luajit_s('rbac', {op:'authz', sid:sid, q:query})::BOOLEAN)")
    con.execute("SET GLOBAL quack_authentication_function = 'rbac_authn'")
    con.execute("SET GLOBAL quack_authorization_function = 'rbac_authz'")
    # verify hooks actually took (silent-drop trap)
    hooks = con.execute(
        "SELECT name, value FROM duckdb_settings() WHERE name IN "
        "('quack_authentication_function','quack_authorization_function')").fetchall()
    assert all(v in ('rbac_authn', 'rbac_authz') for _, v in hooks), \
        f"hooks not registered: {hooks}"
    print("hooks verified:", hooks, flush=True)
    print("rbac status:", con.execute("SELECT luajit_s('rbac', {op:'status'})").fetchall(), flush=True)

    row = con.execute(
        "SELECT ticket FROM quackhole_serve(token := ?, target := ?, auto_serve := true)",
        [args.token, f"127.0.0.1:{args.port}"]
    ).fetchone()
    with open(args.ticket, "w") as f:
        f.write(row[0] + "\n")
    print("SERVER_READY ticket_len:", len(row[0]), "ticket:", args.ticket, flush=True)
    time.sleep(7200)


if __name__ == "__main__":
    main()
