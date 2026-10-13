#!/usr/bin/env python3
"""quackhole-rbac client: attach to a quackhole-served DuckDB and run RBAC checks.

Two auth layers are used (verified 2026-09):
  1. quackhole_attach(ticket)  — tunnel layer, uses the ticket's shared token.
  2. DROP + recreate the 'qh_<endpoint>' secret with a PER-USER token, re-ATTACH —
     quack app-layer authn then maps the token to a user, authz enforces tables.

Usage:
    python client.py --ticket /tmp/qh_rbac_ticket.txt --token researcher-tok \
        --sql "SELECT count(*) FROM r.public_data"
    python client.py --ticket ... --token viewer-tok --sql "..." --via qq   # server-side quack_query
    python client.py --ticket ... --matrix                                   # full test matrix

Options:
    --ticket   quackhole ticket file (default: /tmp/qh_rbac_ticket.txt)
    --token    per-user token (default: researcher-tok)
    --sql      SQL to run (default: SELECT count(*) FROM r.public_data)
    --via      attach (default) or qq (quack_query, guaranteed server-side)
    --matrix   run the full pass/deny matrix used in verification
"""
import argparse, os, sys, tempfile

try:
    import duckdb
except ImportError:
    sys.exit("duckdb not installed: uv venv && uv pip install duckdb")


def read_ticket(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("qh1_"):
                return line
    sys.exit(f"no qh1_ ticket found in {path}")


def connect(ticket, allow_unsigned=False):
    cfg = {"allow_unsigned_extensions": "true"} if allow_unsigned else {}
    con = duckdb.connect(config=cfg)
    con.execute("INSTALL quack; LOAD quack;")
    con.execute("INSTALL quackhole FROM community; LOAD quackhole;")
    con.execute(f"CALL quackhole_attach('{ticket}', name := 'r')")
    rows = con.execute("SELECT name, scope FROM duckdb_secrets() WHERE type='quack'").fetchall()
    secret_name = rows[0][0]
    scope = rows[0][1][0] if isinstance(rows[0][1], list) else rows[0][1]
    return con, secret_name, scope


def as_user(con, secret_name, scope, token):
    """Drop tunnel-token secret, recreate with per-user token, re-attach."""
    con.execute(f"DROP SECRET {secret_name}")
    con.execute(f"CREATE SECRET {secret_name} (TYPE quack, TOKEN '{token}', SCOPE '{scope}')")
    try:
        con.execute("DETACH r")
    except Exception:
        pass
    con.execute(f"ATTACH '{scope}' AS r")


def run(con, secret_name, scope, token, sql, via):
    as_user(con, secret_name, scope, token)
    if via == "qq":
        esc = sql.replace("'", "''")
        return con.execute(
            f"FROM quack_query('{scope}', '{esc}', token := '{token}')").fetchall()
    return con.execute(sql).fetchall()


def attempt(con, secret_name, scope, label, token, sql, via="qq"):
    try:
        res = run(con, secret_name, scope, token, sql, via)
        print(f"[PASS] {label}: rows={res}", flush=True)
    except Exception as e:
        msg = str(e).strip().split("\n")[0][:150]
        print(f"[DENY] {label}: {msg}", flush=True)


def matrix(con, secret_name, scope):
    # sample-mode identities (alice=analyst full, bob=viewer limited); for real-mode
    # real-mode servers pass --matrix-tokens "researcher-tok,viewer-tok,evil-tok"
    full_tok, limited_tok, evil_tok = "alice-tok", "bob-tok", "evil-tok"
    print("=== legitimate access ===", flush=True)
    attempt(con, secret_name, scope, "full-role secret_data", full_tok,
            "SELECT * FROM r.secret_data", via="attach")
    attempt(con, secret_name, scope, "full-role public_data", full_tok,
            "SELECT * FROM r.public_data", via="attach")
    attempt(con, secret_name, scope, "limited-role public_data", limited_tok,
            "SELECT * FROM r.public_data", via="attach")
    attempt(con, secret_name, scope, "limited-role secret_data (EXPECT DENY)", limited_tok,
            "SELECT * FROM r.secret_data", via="attach")
    print("=== bypass attempts (all EXPECT DENY) ===", flush=True)
    attempt(con, secret_name, scope, "B1 self-grant role", limited_tok,
            "INSERT INTO user_roles VALUES ('bob','analyst')")
    attempt(con, secret_name, scope, "B2 tamper role_perms", limited_tok,
            "UPDATE role_perms SET can_select=true WHERE role='viewer' AND table_name='secret_data'")
    attempt(con, secret_name, scope, "B3 macro takeover", limited_tok,
            "CREATE OR REPLACE MACRO rbac_authz(sid, query) AS (true)")
    attempt(con, secret_name, scope, "B4 swap authz fn", limited_tok,
            "SET GLOBAL quack_authorization_function = 'quack_nop_authorization'")
    attempt(con, secret_name, scope, "B4b retry after SET", limited_tok,
            "SELECT * FROM secret_data")
    attempt(con, secret_name, scope, "B5 write denied", limited_tok,
            "INSERT INTO public_data VALUES (9,'x')")
    print("=== auth ===", flush=True)
    attempt(con, secret_name, scope, "evil-tok (EXPECT DENY)", evil_tok,
            "SELECT * FROM r.public_data", via="attach")
    print("=== DONE ===", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticket", default=os.path.join(tempfile.gettempdir(), "qh_rbac_ticket.txt"))
    ap.add_argument("--token", default="researcher-tok")
    ap.add_argument("--sql", default="SELECT count(*) FROM r.public_data")
    ap.add_argument("--via", choices=["attach", "qq"], default="attach")
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--allow-unsigned", action="store_true",
                    help="allow_unsigned_extensions (needed on some platforms, e.g. WSL quackhole)")
    args = ap.parse_args()

    ticket = read_ticket(args.ticket)
    con, secret_name, scope = connect(ticket, allow_unsigned=args.allow_unsigned)
    print(f"attached; secret={secret_name[:30]}... scope={scope[:40]}...", flush=True)

    if args.matrix:
        matrix(con, secret_name, scope)
    else:
        try:
            res = run(con, secret_name, scope, args.token, args.sql, args.via)
            print(res, flush=True)
        except Exception as e:
            print("[DENY]", str(e).strip().split("\n")[0][:200], flush=True)


if __name__ == "__main__":
    main()
