#!/bin/bash
# quackhole-rbac 服务启动/停止/状态 — MIMIC mimic_demo.duckdb (210MB, 23对象三层)
# 用法: bash qhctl.sh start|stop|status|restart
set -e
BASE=/Users/sa/pg2parquet
DEPLOY=$BASE/quackhole-deploy
VENV=$BASE/.qhvenv
DB=$BASE/mimic_demo.duckdb
LUA=$DEPLOY/rbac_mimic.lua
TICKET=$DEPLOY/ticket.txt
TOKEN=qh-demo-20260902
PORT=9495
LOG=$DEPLOY/server.log

start() {
  pkill -f "server.py --db $DB" 2>/dev/null || true
  sleep 1
  cd $DEPLOY
  nohup $VENV/bin/python server.py --db $DB --lua $LUA \
    --ticket $TICKET --token $TOKEN --port $PORT > $LOG 2>&1 &
  echo "started pid=$!"
  sleep 10
  tail -6 $LOG
}

stop() {
  pkill -f "server.py --db $DB" 2>/dev/null && echo stopped || echo "not running"
}

status() {
  if pgrep -f "server.py --db $DB" > /dev/null; then
    echo "RUNNING (pid $(pgrep -f 'server.py --db' | head -1))"
    echo "ticket: $TICKET ($(wc -c < $TICKET) bytes)"
    tail -3 $LOG
  else
    echo "STOPPED"
  fi
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  status) status ;;
  *) echo "usage: $0 start|stop|status|restart" ;;
esac
