#!/bin/zsh

unsetopt BG_NICE 2>/dev/null

APP_DIR="${0:A:h}"
RUNTIME_DIR="/tmp/pulsepath-$UID"
PID_FILE="$RUNTIME_DIR/server.pid"
LOG_FILE="$RUNTIME_DIR/server.log"
URL="http://127.0.0.1:4173/"

cd "$APP_DIR" || exit 1
mkdir -p "$RUNTIME_DIR"

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(<"$PID_FILE")"
  if [[ "$existing_pid" =~ '^[0-9]+$' ]] && kill -0 "$existing_pid" 2>/dev/null; then
    open "$URL"
    exit 0
  fi
fi

python_bin="$(command -v python3)"
if [[ -z "$python_bin" ]]; then
  echo "Pulsepath could not find Python 3 on this Mac."
  echo "Press Return to close this window."
  read
  exit 1
fi

nohup "$python_bin" "$APP_DIR/pulsepath.py" --no-open --port 4173 >"$LOG_FILE" 2>&1 </dev/null &
server_pid=$!
echo "$server_pid" > "$PID_FILE"
disown "$server_pid" 2>/dev/null

for attempt in {1..50}; do
  if /usr/bin/curl -fsS "$URL/api/status" 2>/dev/null | /usr/bin/grep -q '"collector"'; then
    open "$URL"
    exit 0
  fi
  sleep 0.1
done

echo "Pulsepath could not start. The diagnostic output is below:"
echo
/usr/bin/tail -n 25 "$LOG_FILE"
echo
echo "Press Return to close this window."
read
exit 1
