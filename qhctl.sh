#!/bin/bash
# quackhole-rbac service control: start / stop / status / restart
#
# This is a PORTABLE example wrapper. Override the deployment values via
# environment variables instead of editing the file (keeps it usable by any
# operator and free of a hardcoded private tree / credential):
#
#   QH_BASE    deploy dir holding server.py + the rbac .lua   (default: script dir)
#   QH_DB      DuckDB file to serve                           (default: $QH_BASE/rbac.duckdb)
#   QH_LUA     rbac policy .lua (default: $QH_BASE/rbac_mimic.lua)
#   QH_TICKET  where the server writes the ticket             (default: $QH_BASE/ticket.txt)
#   QH_TOKEN   tunnel shared token (default: $QH_TOKEN or env QUACKHOLE_TOKEN)
#   QH_PORT    quack port (default: 9495; 9494 is often taken by WSL relay on Windows)
#   QH_PY      python with duckdb installed (default: $QH_BASE/.venv/bin/python or 'python3')
#   QH_ARGS    extra server.py args (e.g. "--sample --force")
#
# Example:
#   QH_DB=/data/mimic.duckdb QH_TOKEN=*** QH_PORT=9495 bash qhctl.sh start
set -e
BASE="${QH_BASE:-$(cd "$(dirname "$0")" && pwd)}"
DB="${QH_DB:-$BASE/rbac.duckdb}"
LUA="${QH_LUA:-$BASE/rbac_mimic.lua}"
TICKET="${QH_TICKET:-$BASE/ticket.txt}"
TOKEN="${QH_TOKEN:-${QUACKHOLE_TOKEN:-qh-demo-token}}"
PORT="${QH_PORT:-9495}"
PY="${QH_PY:-$BASE/.venv/bin/python}"; [ -x "$PY" ] || PY="python3"
PIDFILE="${QH_PIDFILE:-$BASE/server.pid}"
LOG="${QH_LOG:-$BASE/server.log}"
ARGS="${QH_ARGS:-}"

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

start() {
  if is_running; then echo "already running (pid $(cat "$PIDFILE"))"; return; fi
  # launch with a token passed via env, not argv (keeps the secret out of `ps`)
  QUACKHOLE_TOKEN="$TOKEN" nohup "$PY" "$BASE/server.py" \
    --db "$DB" --lua "$LUA" --ticket "$TICKET" --port "$PORT" $ARGS \
    > "$LOG" 2>&1 &
  echo $! > "$PIDFILE"
  # readiness gate: wait for SERVER_READY or an error, not a blind sleep
  local i
  for i in $(seq 1 30); do
    if grep -q "SERVER_READY" "$LOG" 2>/dev/null; then
      echo "ready (pid $(cat "$PIDFILE")) ticket: $TICKET"; tail -3 "$LOG"; return 0
    fi
    if grep -qE "Traceback|SystemExit|Error:" "$LOG" 2>/dev/null; then
      echo "FAILED to start — last log lines:"; tail -6 "$LOG"; return 1
    fi
    sleep 2
  done
  echo "timed out waiting for readiness — check $LOG"; tail -6 "$LOG"; return 1
}

stop() {
  if is_running; then
    kill "$(cat "$PIDFILE")" 2>/dev/null && echo "stopped (pid $(cat "$PIDFILE"))"
  else
    echo "not running"
  fi
  rm -f "$PIDFILE"
}

status() {
  if is_running; then
    echo "RUNNING (pid $(cat "$PIDFILE"))"
    [ -f "$TICKET" ] && echo "ticket: $TICKET ($(wc -c < "$TICKET") bytes, perms $(stat -f '%Sp' "$TICKET" 2>/dev/null || stat -c '%A' "$TICKET" 2>/dev/null))"
    tail -3 "$LOG"
  else
    echo "STOPPED"
  fi
}

case "${1:-status}" in
  start) start ;; stop) stop ;; restart) stop; start ;; status) status ;;
  *) echo "usage: $0 start|stop|status|restart (see header for QH_* overrides)" ;;
esac
