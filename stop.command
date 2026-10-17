#!/bin/zsh

RUNTIME_DIR="/tmp/pulsepath-$UID"
PID_FILE="$RUNTIME_DIR/server.pid"
APP_DIR="${0:A:h}"

if [[ -f "$PID_FILE" ]]; then
  server_pid="$(<"$PID_FILE")"
else
  server_pid="$(/usr/sbin/lsof -nP -t -a -iTCP:4173 -sTCP:LISTEN 2>/dev/null | /usr/bin/head -n 1)"
  if [[ -n "$server_pid" ]]; then
    server_cwd="$(/usr/sbin/lsof -a -p "$server_pid" -d cwd -Fn 2>/dev/null | /usr/bin/sed -n 's/^n//p')"
    if [[ "$server_cwd" != "$APP_DIR" ]]; then
      server_pid=""
    fi
  fi
fi

if [[ -z "$server_pid" ]]; then
  echo "Pulsepath is not running."
  sleep 1
  exit 0
fi

if [[ "$server_pid" =~ '^[0-9]+$' ]] && kill -0 "$server_pid" 2>/dev/null; then
  kill "$server_pid"
  for attempt in {1..20}; do
    kill -0 "$server_pid" 2>/dev/null || break
    sleep 0.1
  done
fi

rm -f "$PID_FILE"
echo "Pulsepath stopped."
sleep 1
