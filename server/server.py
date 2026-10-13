#!/usr/bin/env python3
"""quackhole-rbac server v3: luajit RBAC policy + quack authn/authz hooks + quackhole P2P tunnel.

Runs the RBAC-over-quackhole server on top of any DuckDB file. External clients
attach via the printed quackhole ticket; every query is enforced server-side by
the luajit rbac policy engine (v3: default-deny over the whole catalog, RBAC
metadata always denied, function/keyword blacklist, table-level SELECT).

Usage:
    python server.py [--db PATH] [--lua PATH] [--ticket PATH] [--token TOK] [--port N]
                     [--sample [--force]]
    --db       DuckDB file to serve (default: env QUACKHOLE_DB or ./rbac.duckdb)
    --lua      rbac policy lua (default: ./rbac_mimic.lua next to this script; ignored in --sample)
    --ticket   where to write the ticket (default: /tmp/qh_rbac_ticket.txt)
    --token    tunnel shared token (default: env QUACKHOLE_TOKEN or 'qh-tok')
    --port     quack port for quackhole to auto-serve (default 9494; WSL relay uses it on Windows)
    --sample   create a sample DB (secret_data/public_data/other_data) + demo roles
    --force    with --sample, allow overwriting an existing --db file (default: refuse)
    --luajit-so path to a locally-built luajit.duckdb_extension (unsigned);
               default: install luajit FROM community

Environment:
    QUACKHOLE_DB, QUACKHOLE_TOKEN — same as --db / --token

RBAC tables (created by the policy engine's setup op):
    quack_tokens(auth_token PK, user_name)     — token -> user
    quack_sessions(sid PK, user_name)          — connection -> user (written by authn)
    user_roles(user_name, role)                — user -> role
    role_perms(role, table_name, can_select, can_write) — role -> table perms (PK role+table)

Seeding is idempotent (DELETE then INSERT of identities + a policy-driven grant
pass), so the server can be restarted against the same DB. Grants are derived
from the policy engine's own `tables` list, not by regex-scraping the .lua.
"""
import argparse, os, signal, sys, tempfile, time

try:
    import duckdb
except ImportError:
    sys.exit("duckdb not installed: uv venv && uv pip install 'duckdb>=1.5.5'")

HERE = os.path.dirname(os.path.abspath(__file__))

STOP = {"flag": False}


def on_signal(signum, _frame):
    STOP["flag"] = True


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=os.environ.get("QUACKHOLE_DB", "./rbac.duckdb"))
    p.add_argument("--lua", default=os.path.join(HERE, "rbac_mimic.lua"))
    p.add_argument("--ticket", default=os.path.join(tempfile.gettempdir(), "qh_rbac_ticket.txt"))
    p.add_argument("--token", default=os.environ.get("QUACKHOLE_TOKEN", "qh-tok"))
    p.add_argument("--port", type=int, default=9494)
    p.add_argument("--sample", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="with --sample, allow overwriting an existing --db file")
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


def seed_sample(con):
    con.execute("CREATE TABLE IF NOT EXISTS secret_data (id INTEGER, name VARCHAR)")
    con.execute("CREATE TABLE IF NOT EXISTS public_data (id INTEGER, name VARCHAR)")
    con.execute("CREATE TABLE IF NOT EXISTS other_data (id INTEGER, name VARCHAR)")
    con.execute("INSERT INTO secret_data VALUES (1,'classified'),(2,'top-secret')")
    con.execute("INSERT INTO public_data VALUES (1,'open'),(2,'public')")
    con.execute("INSERT INTO other_data VALUES (1,'other')")


def reseed_identities(con, mode, token):
    """Idempotent identity + grant seeding (restart-safe: delete demo rows, re-insert)."""
    demo_tokens = ['alice-tok', 'bob-tok', 'researcher-tok', 'viewer-tok']
    demo_users = ['alice', 'bob', 'researcher', 'viewer', 'tunnel']
    con.execute("DELETE FROM quack_tokens WHERE auth_token IN "
                f"({','.join('?' * len(demo_tokens))}) OR user_name IN "
                f"({','.join('?' * len(demo_users))}) OR auth_token = ?",
                [*[t for t in demo_tokens], *[u for u in demo_users], token])
    con.execute("DELETE FROM user_roles WHERE user_name IN (" +
                ",".join("?" * len(demo_users)) + ")", demo_users)
    con.execute("DELETE FROM role_perms WHERE role IN ('analyst','viewer','tunnel_role',"
                "'researcher_role','viewer_role')")

    if mode == "sample":
        # analyst: full (3 demo tables); viewer: public only; tunnel: public only (minimal)
        con.execute("INSERT INTO quack_tokens VALUES ('alice-tok','alice'),('bob-tok','bob'),(?, 'tunnel')", [token])
        con.execute("INSERT INTO user_roles VALUES ('alice','analyst'),('bob','viewer'),('tunnel','tunnel_role')")
        con.execute("INSERT INTO role_perms VALUES "
                    "('analyst','secret_data',true,false),('analyst','public_data',true,false),("
                    "'analyst','other_data',true,false),"
                    "('viewer','public_data',true,false),"
                    "('tunnel_role','public_data',true,false)")
        print("seeded: alice/analyst(full), bob/viewer(public), tunnel(public)", flush=True)
    else:
        # real mode: researcher gets every protected data table; viewer gets s_* (public
        # terminology layer); tunnel gets minimal (admissions). RBAC meta never granted.
        protected = [t for t in (con.execute(
            "SELECT luajit_s('rbac', {op:'tables'})").fetchone()[0] or "").split(",") if t]
        data_tables = [t for t in protected
                       if not t.startswith(("quack_", "user_", "role_"))]
        viewer_tables = [t for t in data_tables if t.startswith("s_")]
        perms = [f"('researcher_role','{t}',true,false)" for t in data_tables]
        perms += [f"('viewer_role','{t}',true,false)" for t in viewer_tables]
        if 'admissions' in data_tables:
            perms.append("('tunnel_role','admissions',true,false)")
        con.execute("INSERT INTO quack_tokens VALUES "
                    "('researcher-tok','researcher'),('viewer-tok','viewer'),(?, 'tunnel')", [token])
        con.execute("INSERT INTO user_roles VALUES "
                    "('researcher','researcher_role'),('viewer','viewer_role'),('tunnel','tunnel_role')")
        if perms:
            con.execute("INSERT INTO role_perms VALUES " + ",".join(perms))
        print(f"seeded: researcher={len(data_tables)} tables, viewer={len(viewer_tables)} tables "
              f"(RBAC meta excluded)", flush=True)


def verify_hooks(con):
    rows = dict(con.execute(
        "SELECT name, value FROM duckdb_settings() WHERE name IN "
        "('quack_authentication_function','quack_authorization_function')").fetchall())
    # explicit exact check — never `all([])` (an empty result must fail)
    expected = {'quack_authentication_function': 'rbac_authn',
                'quack_authorization_function': 'rbac_authz'}
    missing = [k for k in expected if rows.get(k) != expected[k]]
    if missing:
        raise SystemExit(f"quack hooks not registered: {rows} (missing: {missing})")
    return rows


def main():
    args = parse_args()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    if args.sample:
        if os.path.exists(args.db) and not args.force:
            raise SystemExit(
                f"--sample refuses to overwrite existing {args.db!r}. "
                "Use a fresh path or pass --force to reset the demo database.")
        if os.path.exists(args.db):
            os.remove(args.db)

    con = connect(args.db, args.luajit_so)
    if args.sample:
        seed_sample(con)

    # --- RBAC policy engine (compile + create the 4 RBAC tables) ---
    lua = os.path.join(HERE, "rbac_sample.lua") if args.sample else args.lua
    with open(lua, "r", encoding="utf-8-sig") as f:
        lua_src = f.read()
    con.execute("SELECT * FROM luajit_module(mode := 'compile', sql_name := 'rbac', source := $1)",
                [lua_src])
    print("rbac setup:", con.execute("SELECT luajit_s('rbac', {op: 'setup'})").fetchall(), flush=True)

    # --- idempotent identity + grant seeding ---
    reseed_identities(con, "sample" if args.sample else "real", args.token)

    # --- quack + quackhole (MUST load BEFORE SET GLOBAL hooks) ---
    con.execute("INSTALL quack; LOAD quack;")
    con.execute("INSTALL quackhole FROM community; LOAD quackhole;")

    # --- quack authn/authz hooks ---
    con.execute("CREATE MACRO rbac_authn(sid, ct, st) AS "
                "(luajit_s('rbac', {op:'authn', sid:sid, client_token:ct, server_token:st})::BOOLEAN)")
    con.execute("CREATE MACRO rbac_authz(sid, query) AS "
                "(luajit_s('rbac', {op:'authz', sid:sid, q:query})::BOOLEAN)")
    con.execute("SET GLOBAL quack_authentication_function = 'rbac_authn'")
    con.execute("SET GLOBAL quack_authorization_function = 'rbac_authz'")
    print("hooks verified:", verify_hooks(con), flush=True)
    print("rbac status:", con.execute("SELECT luajit_s('rbac', {op:'status'})").fetchall(), flush=True)

    row = con.execute(
        "SELECT ticket FROM quackhole_serve(token := ?, target := ?, auto_serve := true)",
        [args.token, f"127.0.0.1:{args.port}"]
    ).fetchone()
    if not row or not row[0]:
        raise SystemExit("quackhole_serve returned no ticket")
    ticket = row[0]
    # write ticket atomically with owner-only perms (it is the tunnel credential)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(args.ticket)) or ".")
    try:
        os.write(fd, (ticket + "\n").encode())
        os.fchmod(fd, 0o600)
        os.replace(tmp, args.ticket)
    finally:
        os.close(fd)
    print(f"SERVER_READY ticket_len:{len(ticket)} ticket:{args.ticket}", flush=True)

    # --- serve until signalled ---
    while not STOP["flag"]:
        time.sleep(0.5)
    print("shutting down (signal received)", flush=True)
    try:
        con.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
