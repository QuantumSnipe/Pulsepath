#!/bin/zsh

unsetopt BG_NICE 2>/dev/null

APP_DIR="${0:A:h}"
if [[ -n "${HOME:-}" ]]; then
  RUNTIME_DIR="${HOME}/Library/Caches/Pulsepath"
else
  runtime_parent="${TMPDIR:-/tmp}"
  RUNTIME_DIR="${runtime_parent%/}/Pulsepath"
fi
PID_FILE="$RUNTIME_DIR/server.pid"
LOG_FILE="$RUNTIME_DIR/server.log"
URL="http://127.0.0.1:4173/"

cd "$APP_DIR" || exit 1

# Refuse a planted path before creating or trusting the pid and log files.
if [[ -L "$RUNTIME_DIR" ]]; then
  echo "Pulsepath refused to start: ${RUNTIME_DIR} is a symlink."
  exit 1
fi
if [[ -e "$RUNTIME_DIR" && ! -d "$RUNTIME_DIR" ]]; then
  echo "Pulsepath refused to start: ${RUNTIME_DIR} is not a directory."
  exit 1
fi
if [[ ! -d "$RUNTIME_DIR" ]]; then
  /bin/mkdir -p "$(/usr/bin/dirname "$RUNTIME_DIR")" || exit 1
  /bin/mkdir -m 700 "$RUNTIME_DIR" || exit 1
fi
if [[ -L "$RUNTIME_DIR" || ! -d "$RUNTIME_DIR" ]]; then
  echo "Pulsepath refused to start: ${RUNTIME_DIR} is a symlink."
  exit 1
fi
runtime_owner="$(/usr/bin/stat -f '%u' "$RUNTIME_DIR")"
if [[ "$runtime_owner" != "$UID" ]]; then
  echo "Pulsepath refused to start: ${RUNTIME_DIR} is not owned by this user."
  exit 1
fi

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
  # /api/status requires the session token, which only the served page receives.
  if /usr/bin/curl -fsS "$URL" 2>/dev/null | /usr/bin/grep -q 'name="pulsepath-token"'; then
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
