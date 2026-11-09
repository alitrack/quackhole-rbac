#!/usr/bin/env python3
"""quackhole-rbac client v3: attach to a quackhole-served DuckDB, swap to a per-user
token, and run queries / the RBAC verification matrix.

Two auth layers (verified against the v3 server):
  1. quackhole_attach(ticket) — tunnel layer, uses the ticket's shared token.
  2. DROP + recreate the 'qh_<endpoint>' secret with a PER-USER token, re-ATTACH —
     quack app-layer authn maps token→user, authz enforces table grants.

v3 changes:
  * Deterministic secret selection: pick the quack secret whose name is the
    auto-created 'qh_*' secret for the attached endpoint, and require EXACTLY one.
  * Tokens and SQL are escaped (single-quote doubling) before interpolation.
  * Errors are classified: AUTHN (token rejected) vs AUTHZ (authorization) vs
    other (infrastructure / catalog) — no more "everything is [DENY]".
  * --matrix-tokens / --matrix-tables make the matrix usable in real mode, not
    sample-only. A missing/unknown token now reports AUTHN, not a false DENY.
  * The matrix asserts expected outcomes and exits non-zero on any unexpected result.

Usage:
    python client.py --ticket /tmp/qh_rbac_ticket.txt --token alice-tok \
        --sql "SELECT count(*) FROM r.public_data"
    python client.py --ticket ... --token bob-tok --sql "..." --via qq   # server-side quack_query
    python client.py --ticket ... --matrix                                # sample-mode matrix
    python client.py --ticket ... --matrix --matrix-tokens "researcher-tok,viewer-tok,evil-tok" \
        --matrix-tables "secret=secret_data,public=public_data"          # real-mode matrix

Options:
    --ticket        quackhole ticket file (default: /tmp/qh_rbac_ticket.txt)
    --token         per-user token (default: researcher-tok)
    --sql           SQL to run (default: SELECT count(*) FROM r.public_data)
    --via           attach (default) or qq (quack_query, guaranteed server-side)
    --matrix        run the verification matrix
    --matrix-tokens comma list: full,limited,evil (default: alice-tok,bob-tok,evil-tok)
    --matrix-tables comma list name=table for secret and public
                    (default: secret=secret_data,public=public_data)
    --allow-unsigned allow_unsigned_extensions (some platforms, e.g. WSL quackhole)
"""
import argparse, os, sys, tempfile

try:
    import duckdb
except ImportError:
    sys.exit("duckdb not installed: uv venv && uv pip install 'duckdb>=1.5.5'")


def esc(s):
    return str(s).replace("'", "''")


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
    con.execute(f"CALL quackhole_attach('{esc(ticket)}', name := 'r')")
    rows = con.execute(
        "SELECT name, scope FROM duckdb_secrets() "
        "WHERE type = 'quack' AND name LIKE 'qh\\_%' ESCAPE '\\'").fetchall()
    if len(rows) != 1:
        sys.exit(f"expected exactly one qh_* quack secret, found {len(rows)}: "
                 f"{[r[0] for r in rows]} — refusing to guess which to swap")
    secret_name = rows[0][0]
    scope = rows[0][1]
    scope = scope[0] if isinstance(scope, list) else scope
    return con, secret_name, scope


def as_user(con, secret_name, scope, token):
    """Drop the tunnel-token secret, recreate with the per-user token, re-attach."""
    con.execute(f"DROP SECRET {secret_name}")
    con.execute(f"CREATE SECRET {secret_name} (TYPE quack, TOKEN '{esc(token)}', SCOPE '{esc(scope)}')")
    try:
        con.execute("DETACH r")
    except duckdb.Error as e:
        # On a fresh attach 'r' may not be detached; only ignore "does not exist", re-raise real errors
        if "does not exist" not in str(e).lower():
            raise
    con.execute(f"ATTACH '{esc(scope)}' AS r")


def classify_error(e):
    """Classify a raised error into AUTHN / AUTHZ / other so the matrix is honest."""
    msg = str(e)
    low = msg.lower()
    if "authentication" in low or "token" in low and "fail" in low or "invalid token" in low:
        return "AUTHN"
    if "authorization" in low or "permission" in low or "rbac" in low or "denied" in low:
        return "AUTHZ"
    return "OTHER"


def run(con, secret_name, scope, token, sql, via):
    as_user(con, secret_name, scope, token)
    if via == "qq":
        return con.execute(
            f"FROM quack_query('{esc(scope)}', '{esc(sql)}', token := '{esc(token)}')").fetchall()
    return con.execute(sql).fetchall()


def attempt(con, secret_name, scope, label, token, sql, via="qq", expect=None):
    """Run one case. Returns True if the outcome matches `expect` (None = don't assert)."""
    try:
        res = run(con, secret_name, scope, token, sql, via)
        outcome = "PASS"
        detail = f"rows={res}"
    except Exception as e:
        kind = classify_error(e)
        first = str(e).strip().split("\n")[0][:150]
        outcome = kind  # AUTHN / AUTHZ / OTHER
        detail = first
    line = f"[{outcome}] {label}: {detail}"
    if expect is not None:
        ok = (outcome == expect)
        line = f"[{'OK ' if ok else 'BAD'}] want={expect:5} got={outcome:5} | {line}"
        print(line, flush=True)
        return ok
    print(line, flush=True)
    return True


def matrix(con, secret_name, scope, toks, tables):
    full, limited, evil = toks
    secret, public = tables["secret"], tables["public"]
    results = []

    def case(label, token, sql, via, expect):
        results.append(attempt(con, secret_name, scope, label, token, sql, via, expect))

    print("=== legitimate access ===", flush=True)
    case(f"full-role read {secret}", full, f"SELECT * FROM r.{secret}", "attach", "PASS")
    case(f"full-role read {public}", full, f"SELECT * FROM r.{public}", "attach", "PASS")
    case(f"limited-role read {public}", limited, f"SELECT * FROM r.{public}", "attach", "PASS")
    case(f"limited-role read {secret} (EXPECT DENY)", limited, f"SELECT * FROM r.{secret}", "attach", "AUTHZ")

    print("=== bypass attempts (all EXPECT DENY) ===", flush=True)
    case("B1 self-grant role", limited,
         f"INSERT INTO user_roles VALUES ('{esc('bob')}','analyst')", "qq", "AUTHZ")
    case("B2 tamper role_perms", limited,
         f"UPDATE role_perms SET can_select=true WHERE role='viewer' AND table_name='{esc(secret)}'", "qq", "AUTHZ")
    case("B3 macro takeover", limited,
         "CREATE OR REPLACE MACRO rbac_authz(sid, query) AS (true)", "qq", "AUTHZ")
    case("B4 swap authz fn", limited,
         "SET GLOBAL quack_authorization_function = 'quack_nop_authorization'", "qq", "AUTHZ")
    case("B4b retry after SET", limited, f"SELECT * FROM {secret}", "qq", "AUTHZ")
    case("B5 write denied", limited, f"INSERT INTO {public} VALUES (9,'x')", "qq", "AUTHZ")
    # v3-specific vectors
    case("B6 uppercase table ref", limited, f"SELECT * FROM r.{secret.upper()}", "qq", "AUTHZ")
    case("B7 dump RBAC metadata (quack_tokens)", full, "SELECT * FROM r.quack_tokens", "qq", "AUTHZ")
    case("B8 luajit_s grant shell", limited,
         f"SELECT luajit_s('rbac', {{op:'grant', role:'viewer', tbl:'{esc(secret)}', can_select:true}})", "qq", "AUTHZ")
    case("B9 stacked write", limited, f"SELECT 1; INSERT INTO user_roles VALUES ('{esc('bob')}','analyst')", "qq", "AUTHZ")
    case("B10 install extension", limited, "INSTALL quackhole FROM community", "qq", "AUTHZ")
    case("B11 load extension", limited, "LOAD luajit", "qq", "AUTHZ")
    case("legit CTE read (EXPECT PASS)", full,
         f"WITH x AS (SELECT * FROM r.{public}) SELECT * FROM x", "attach", "PASS")

    print("=== auth ===", flush=True)
    case("evil-tok (EXPECT AUTHN)", evil, f"SELECT * FROM r.{public}", "attach", "AUTHN")

    print("=== DONE ===", flush=True)
    return all(results)


def parse_kv(arg):
    out = {}
    for part in arg.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ticket", default=os.path.join(tempfile.gettempdir(), "qh_rbac_ticket.txt"))
    ap.add_argument("--token", default="researcher-tok")
    ap.add_argument("--sql", default="SELECT count(*) FROM r.public_data")
    ap.add_argument("--via", choices=["attach", "qq"], default="attach")
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--matrix-tokens", default="alice-tok,bob-tok,evil-tok")
    ap.add_argument("--matrix-tables", default="secret=secret_data,public=public_data")
    ap.add_argument("--allow-unsigned", action="store_true")
    args = ap.parse_args()

    ticket = read_ticket(args.ticket)
    con, secret_name, scope = connect(ticket, allow_unsigned=args.allow_unsigned)
    print(f"attached; secret={secret_name[:30]}... scope={scope[:40]}", flush=True)

    if args.matrix:
        toks = [t for t in args.matrix_tokens.split(",")]
        if len(toks) != 3:
            sys.exit("--matrix-tokens needs exactly 3 comma-separated tokens: full,limited,evil")
        tables = parse_kv(args.matrix_tables)
        tables.setdefault("secret", "secret_data")
        tables.setdefault("public", "public_data")
        ok = matrix(con, secret_name, scope, toks, tables)
        con.close()
        sys.exit(0 if ok else 1)
    else:
        try:
            res = run(con, secret_name, scope, args.token, args.sql, args.via)
            print(res, flush=True)
            con.close()
        except Exception as e:
            print(f"[{classify_error(e)}]", str(e).strip().split("\n")[0][:200], flush=True)
            con.close()
            sys.exit(2)


if __name__ == "__main__":
    main()
