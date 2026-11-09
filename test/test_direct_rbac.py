#!/usr/bin/env python3
"""test_direct_rbac.py — LAN direct mode (--direct) E2E.

Starts server.py --direct --sample on a scratch DB + port, waits for
SERVER_READY, then verifies over a real quack connection that:
  - viewer token CAN read public_data
  - viewer token is DENIED secret_data (error surfaces client-side)
  - write is DENIED (default-deny)
  - RBAC metadata tables are DENIED

Run:  python3 test/test_direct_rbac.py [duckdb_cli_path]
Exit: 0 all pass, 1 any failure.
"""
import os, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = sys.argv[1] if len(sys.argv) > 1 else "/home/lhy/.local/bin/duckdb156"
PORT = 19501
TOKEN = "direct-rbac-tok"
DB = os.path.join(tempfile.gettempdir(), "qh_direct_test.duckdb")

for f in (DB, DB + ".wal"):
    if os.path.exists(f):
        os.remove(f)

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

PORT = free_port()

srv = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "..", "server", "server.py"),
     "--direct", "--sample", "--db", DB, "--port", str(PORT),
     "--token", TOKEN, "--ticket", DB + ".endpoint"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

ready = False
t0 = time.time()
while time.time() - t0 < 90:
    line = srv.stdout.readline()
    if not line:
        break
    print("[srv]", line.rstrip())
    if "SERVER_READY" in line:
        ready = True
        break
if not ready:
    srv.kill()
    sys.exit("server never became ready")

# allow the listener to settle
for _ in range(50):
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", PORT)) == 0:
            break
    time.sleep(0.1)

def client_sql(tok, sql):
    """Run one statement as a fresh client with the given token.

    Uses the same python duckdb the server runs on (same engine version,
    so the same quack extension binary loads) — the 1.5.x CLI would fetch
    a quack build the 2.0 server can't talk to.
    """
    import duckdb as _ddb
    c = _ddb.connect()
    c.execute("LOAD quack")
    c.execute(f"ATTACH 'quack:127.0.0.1:{PORT}' AS r (TOKEN '{tok}')")
    try:
        c.execute(sql)
        out = str(c.fetchall())
        c.close()
        return 0, out, ""
    except Exception as e:
        c.close()
        return 1, "", str(e)

results = []

def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")

# 1. viewer reads public_data (allowed)
rc, out, err = client_sql("bob-tok", "SELECT count(*) FROM r.public_data;")
check("viewer_read_public", rc == 0 and "2" in out, f"rc={rc} out={out.strip()[:80]} err={err.strip()[:120]}")

# 2. viewer denied secret_data
rc, out, err = client_sql("bob-tok", "SELECT count(*) FROM r.secret_data;")
check("viewer_denied_secret", rc != 0, f"rc={rc} err={err.strip()[:120]}")

# 3. write denied
rc, out, err = client_sql("bob-tok", "INSERT INTO r.public_data VALUES (9,'x');")
check("write_denied", rc != 0, f"rc={rc} err={err.strip()[:120]}")

# 4. metadata denied
rc, out, err = client_sql("bob-tok", "SELECT count(*) FROM r.quack_tokens;")
check("meta_denied", rc != 0, f"rc={rc} err={err.strip()[:120]}")

# 5. analyst reads secret_data (allowed)
rc, out, err = client_sql("alice-tok", "SELECT count(*) FROM r.secret_data;")
check("analyst_read_secret", rc == 0 and "2" in out, f"rc={rc} out={out.strip()[:80]} err={err.strip()[:120]}")

# 6. bad token rejected
rc, out, err = client_sql("wrong-tok", "SELECT count(*) FROM r.public_data;")
check("bad_token_rejected", rc != 0, f"rc={rc} err={err.strip()[:120]}")

srv.kill()
fails = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} passed" + (f", FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
