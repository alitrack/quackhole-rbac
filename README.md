# quackhole-rbac

**A remote DuckDB query service built on three layers: the quackhole P2P tunnel, quack app-layer authentication, and a LuaJIT RBAC policy for table-level, read-only authorization.**

The DuckDB database file stays on the server; external clients attach over an encrypted P2P tunnel and receive query results only — no public IP, no open ports, no VPN, no TLS certificates. Each user has an independent token and a role-scoped, table-level, read-only grant. Write operations are denied by default. (Granted users can read an entire table they are authorized for — there is no row-level or column-level control.)

> A Chinese version of this README lives in [README_CN.md](README_CN.md).

```
External client ──quackhole (iroh P2P encrypted tunnel, no public IP)──▶ Your server
              │                                                          ├─ quack (app-layer authn: token → user)
              └─ receives query results only                            ├─ luajit rbac.lua (role → table-level permissions)
                                                                        └─ DuckDB data files (stay on the server)
```

## Why these three layers

| Layer | Tool | Responsibility |
|---|---|---|
| Tunnel | [quackhole](https://github.com/smithclay/quackhole) (DuckDB community extension) | iroh P2P encrypted channel — no public IP / port / certificate; anyone holding the ticket can connect |
| Authentication | [quack](https://duckdb.org/quack/) (official DuckDB protocol) | `quack_authentication_function` maps a token to a user |
| Authorization | [duckdb-luajit](https://github.com/alitrack/duckdb-luajit) + `rbac.lua` | `quack_authorization_function` grants table-level SELECT by role; write statements denied by default |

## Quick start

### Prerequisites

- DuckDB ≥ 1.5.5 (required by quackhole; macOS / Linux / Windows)
- Python ≥ 3.10 with the `duckdb` package (recommended via uv: `uv venv && uv pip install -r requirements.txt`)
- The community extensions (luajit / quack / quackhole) install automatically

### 1. Start the server (the machine that holds the data)

```bash
# Demo mode: auto-creates a sample DB (secret_data / public_data) + demo roles
python server/server.py --sample --token my-tunnel-tok

# Real mode: serve an existing DuckDB data file (e.g. a MIMIC terminology layer)
python server/server.py --db /path/to/mimic_standard.duckdb --token my-tunnel-tok

# On Windows, if 9494 is taken by the WSL relay, add --port 9495
```

On startup the server writes the ticket (a ~165-char `qh1_...` string) to the file named by `--ticket` and prints its length and path. **Guard the ticket like a password** — anyone who holds it can enter the tunnel and authenticates as the `tunnel` identity before any user-token swap.

> In real mode, pre-provision the RBAC tables and grants in the database (see "RBAC model" below), or adjust the seed section of `server.py`.

### 2. Connect a client (from any network)

```bash
# Sample-mode example (matches server.py --sample): token alice-tok, table public_data
python client/client.py --ticket /path/to/ticket.txt --token alice-tok \
    --sql "SELECT count(*) FROM r.public_data"

# Real-mode example: a per-user token and a table in the served DB
python client/client.py --ticket /path/to/ticket.txt --token researcher-tok \
    --sql "SELECT count(*) FROM r.s_mimic_icd_map"

# Run the sample-mode verification matrix (legitimate access + bypass attempts)
python client/client.py --ticket /path/to/ticket.txt --matrix
```

## The two-layer authentication: why the client swaps its secret

quackhole authenticates the **tunnel** with the shared token embedded in the ticket; quack authenticates the **application layer** with a per-user token. So after a client attaches over the tunnel, it must replace the secret that quackhole auto-created with its own per-user token and re-ATTACH — only then does the server's authn hook map the connection to the correct user. `client.py` wraps this for you (`as_user`).

```python
# What client.py does internally (equivalent to the long form in the quackhole docs):
con.execute(f"CALL quackhole_attach('{ticket}', name := 'r')")
# Find the secret quackhole created: named qh_<endpoint-id>, scope is a LIST type
# DROP it, recreate the same-named secret with the per-user token, then DETACH + ATTACH
```

## RBAC model

The RBAC metadata is four tables (created automatically by `rbac.lua`'s `setup`):

| Table | Purpose |
|---|---|
| `quack_tokens(auth_token PK, user_name)` | token → user |
| `quack_sessions(sid PK, user_name)` | connection → user (written by the authn hook; persisted, not a live-connection registry) |
| `user_roles(user_name, role)` | user → role |
| `role_perms(role, table_name, can_select, can_write)` | role → table permissions |

Policy (configurable in `rbac.lua`):

- `protected` — the list of controlled tables (authz checks permissions per table)
- `allow_write = false` — **all write statements are denied** (recommended; set true to allow writes by `can_write` granularity)
- `strict_write = true` — any statement beginning with `WITH` is denied (blocks the `WITH x AS (SELECT 1) INSERT INTO t` bypass, but also denies legitimate CTE reads)

### Seeded roles

Real mode (driven by the `protected` list in `rbac_mimic.lua`):

| Role | Readable tables | Notes |
|---|---|---|
| `researcher_role` | all `protected` data objects, excluding RBAC metadata | full research access |
| `viewer_role` | data objects prefixed `s_` (the public terminology layer) | restricted viewing |
| `tunnel_role` | `admissions` only | minimal privilege for the tunnel's first connection |

Sample mode (demo): `analyst` reads both `public_data` and `secret_data`; `viewer` reads `public_data` only; the tunnel identity reads `public_data` only.

RBAC metadata tables (`quack_*` / `user_*` / `role_*`) are not granted to clients in real mode. (In sample mode the four metadata tables are **not** in the `protected` list — a sample-only gap; see the security review.)

## Verification (sample-mode matrix, tested 2026-09-01)

The `--matrix` run exercises legitimate access plus a set of bypass attempts (self-grant, permission tampering, macro takeover, authorization-function swap, write). In the 2026-09-01 run the outcomes matched expectations:

```
=== legitimate access ===
alice/analyst   read secret_data      → rows returned
bob/viewer      read public_data      → rows returned
bob/viewer      read secret_data      → DENY (authorization)

=== bypass attempts (quack_query forces server-side execution) ===
self-grant role        → DENY
tamper role_perms      → DENY
macro takeover         → DENY
swap authz function    → DENY
retry after swap       → DENY
write (INSERT)         → DENY

=== authentication ===
unregistered token     → DENY (authentication)
```

**This is a dated test run, not a security guarantee.** The matrix is sample-mode only (hardcoded demo tokens/tables), it labels every exception `[DENY]` (so infrastructure errors and authorization failures are not distinguished), and the enforcement below has known limitations.

## Pitfalls (learned the hard way)

1. **The quackhole secret is named `qh_<endpoint-id>`, not `__default_quack`;** `duckdb_secrets().scope` returns a **LIST** — take `[0]`.
2. **Bypass tests must use `quack_query`** (forces server-side execution). Under a plain ATTACH a statement such as `INSERT INTO user_roles` runs on the client locally and never reaches the server policy.
3. The server's `quack_tokens` must register the tunnel token (mapped to the minimal role), or the client's first attach is rejected.
4. `luajit_module` compilation and calls must happen on the **same connection**; on macOS arm64 the luajit community extension installs directly via `INSTALL luajit FROM community`.
5. The public iroh relay is free but has **no SLA** — run your own relay for serious traffic.
6. **SET GLOBAL hooks must come after `LOAD quack`** — setting `quack_authentication_function` before the extension is loaded is silently dropped (`server.py` adds a startup check to catch this).
7. **On Windows, port 9494 is often taken by the WSL localhost relay (wslrelay)** — serve on `--port 9495` on the Windows side; a same-machine serve+client reports "Connecting to ourself is not supported", so test across machines / WSL.
8. **Native Windows Python does not understand `/tmp` or `/d/...` paths** (those are git-bash/WSL conventions) — use `D:/...` or absolute Windows paths for ticket/db.

## Security boundary (read this carefully)

This is a **policy-enforcement sketch, not a hardened authorization boundary.** Known limitations, confirmed by code review:

- **Table checks are case-sensitive substring matches on the raw SQL text, not a parser.** A protected table referenced in uppercase (`SELECT * FROM SECRET_DATA`) escapes the check entirely; an unlisted table can be read with no grant at all; a string literal or comment containing a table name causes a false denial. The correct fix is a parsed, default-deny check over resolved table references.
- **Side-effecting `SELECT`s are classified as reads.** If `luajit_s` is reachable from remote SQL, a client can call `SELECT luajit_s('rbac', {op:'grant', ...})` or `{op:'setup'}` to write permissions or DDL; the "all writes denied" rule does not cover these. (Live reachability depends on the runtime.)
- **The `luajit_s` dispatcher exposes `grant` / `setup` / `authn` with no administrator check** — "administrators only" is a comment, not an enforced gate.
- **The tunnel token is also a valid application credential** (maps to the minimal `tunnel` role), and demo tokens (`researcher-tok`, `alice-tok`, …) are seeded in real mode. Provision private credentials for production.
- Permission metadata lives in the same plane as the data and is protected only by the write-deny policy. **Grant changes must be executed in a local server session.**
- There is **no row-level security or column masking** (queries are not rewritten), and no session revocation/expiry.
- For production use, add: a per-user ticket per client, an `audit_table`, your own iroh relay, and the enforcement fixes above before treating this as a trust boundary.

## Repository layout

```
server/
  server.py          # server: RBAC + quack hooks + quackhole, supports --sample / --db
  rbac_mimic.lua     # MIMIC terminology-layer policy (protected = 23 MIMIC objects)
  rbac_sample.lua    # demo policy (protected = secret_data / public_data)
client/
  client.py          # client: attach + per-user token swap + query / verification matrix
qhctl.sh             # one-command start/stop/status wrapper (example paths/token — parameterize before reuse)
```

## License

MIT (this repo is an integration example; quackhole/iroh are MIT, quack is official DuckDB, duckdb-luajit is MIT). See [LICENSE](LICENSE).
