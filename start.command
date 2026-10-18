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
PORT=4173
# One token file per port, so a launch on 4173 never reads the token of a
# collector that is serving on another port.
TOKEN_FILE="$RUNTIME_DIR/token-${PORT}"
URL="http://127.0.0.1:${PORT}/"

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
# A folder that already existed may be group- or world-writable; tighten it.
/bin/chmod 700 "$RUNTIME_DIR" || exit 1
for runtime_file in "$PID_FILE" "$LOG_FILE" "$TOKEN_FILE"; do
  if [[ -L "$runtime_file" ]]; then
    echo "Pulsepath refused to start: ${runtime_file} is a symlink."
    exit 1
  fi
done

# The token may only go to this checkout's collector. Check that exactly one
# process listens on $PORT, that it runs as this user, and that it is this
# checkout's pulsepath.py (same ps/cwd rules as stop.command). A squatter on
# the port, or a collector from another checkout, fails the check.
listener_is_ours() {
  local listener_pid listener_uid command_line listener_cwd
  listener_pid="$(/usr/sbin/lsof -nP -t -a -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null)"
  [[ "$listener_pid" =~ '^[0-9]+$' ]] || return 1
  listener_uid="$(/bin/ps -p "$listener_pid" -o uid= 2>/dev/null)"
  [[ "${listener_uid// /}" == "$UID" ]] || return 1
  command_line="$(/bin/ps -ww -p "$listener_pid" -o command= 2>/dev/null)"
  [[ "$command_line" == *"$APP_DIR/pulsepath.py"* ]] && return 0
  # A foreground `make run` uses a relative path; require its cwd to match.
  listener_cwd="$(/usr/sbin/lsof -a -p "$listener_pid" -d cwd -Fn 2>/dev/null | /usr/bin/sed -n 's/^n//p')"
  [[ "$listener_cwd" == "$APP_DIR" && "$command_line" == *"pulsepath.py"* ]]
}

# Open the page with the session token in the URL fragment. Browsers never
# send the fragment to the server or in Referer; the page moves it into
# sessionStorage and clears it from the address bar. If the listener on $PORT
# is not this checkout's collector, open the plain page without the token.
open_with_token() {
  local token=""
  if [[ -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" ]] && listener_is_ours; then
    token="$(<"$TOKEN_FILE")"
  fi
  if [[ "$token" =~ '^[A-Za-z0-9_-]{16,128}$' ]]; then
    open "${URL}#k=${token}"
  else
    # The page explains that it needs a launch from start.command.
    open "$URL"
  fi
}

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(<"$PID_FILE")"
  if [[ "$existing_pid" =~ '^[0-9]+$' ]] && kill -0 "$existing_pid" 2>/dev/null \
      && [[ "$(/bin/ps -ww -p "$existing_pid" -o command= 2>/dev/null)" == *"$APP_DIR/pulsepath.py"* ]]; then
    open_with_token
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

# A collector without a pid file (for example `make run`) is already serving
# and has written its token: reuse it instead of starting a second one.
if [[ -s "$TOKEN_FILE" ]] && /usr/bin/curl -fsS -o /dev/null "$URL" 2>/dev/null; then
  open_with_token
  exit 0
fi

# A token left by an earlier run belongs to a collector that is gone.
/bin/rm -f "$TOKEN_FILE"
nohup "$python_bin" "$APP_DIR/pulsepath.py" --no-open --port "$PORT" >"$LOG_FILE" 2>&1 </dev/null &
server_pid=$!
echo "$server_pid" > "$PID_FILE"
disown "$server_pid" 2>/dev/null

for attempt in {1..50}; do
  # The collector writes its token only after it owns the port.
  if [[ -s "$TOKEN_FILE" ]] && /usr/bin/curl -fsS -o /dev/null "$URL" 2>/dev/null; then
    open_with_token
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
