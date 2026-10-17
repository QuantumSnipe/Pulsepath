#!/bin/zsh

if [[ -n "${HOME:-}" ]]; then
  RUNTIME_DIR="${HOME}/Library/Caches/Pulsepath"
else
  runtime_parent="${TMPDIR:-/tmp}"
  RUNTIME_DIR="${runtime_parent%/}/Pulsepath"
fi
PID_FILE="$RUNTIME_DIR/server.pid"
APP_DIR="${0:A:h}"

# Same path rules as start.command. Do not read a pid from a symlink or
# from a directory owned by someone else.
if [[ -L "$RUNTIME_DIR" ]]; then
  echo "Pulsepath refused to stop: ${RUNTIME_DIR} is a symlink."
  exit 1
fi
if [[ -e "$RUNTIME_DIR" ]]; then
  if [[ ! -d "$RUNTIME_DIR" ]]; then
    echo "Pulsepath refused to stop: ${RUNTIME_DIR} is not a directory."
    exit 1
  fi
  runtime_owner="$(/usr/bin/stat -f '%u' "$RUNTIME_DIR")"
  if [[ "$runtime_owner" != "$UID" ]]; then
    echo "Pulsepath refused to stop: ${RUNTIME_DIR} is not owned by this user."
    exit 1
  fi
fi

# Only ever signal this checkout's collector, never whatever process reuses a
# stale pid or a pid someone wrote into the file.
is_pulsepath() {
  local command_line
  command_line="$(/bin/ps -ww -p "$1" -o command= 2>/dev/null)"
  [[ "$command_line" == *"$APP_DIR/pulsepath.py"* ]] && return 0
  # A foreground `make run` uses a relative path; its cwd was checked by lsof.
  [[ -n "$2" && "$command_line" == *"pulsepath.py"* ]]
}

server_pid=""
cwd_verified=""
if [[ -f "$PID_FILE" ]]; then
  server_pid="$(<"$PID_FILE")"
  if ! [[ "$server_pid" =~ '^[0-9]+$' ]] || ! kill -0 "$server_pid" 2>/dev/null || ! is_pulsepath "$server_pid" ""; then
    server_pid=""
  fi
fi
if [[ -z "$server_pid" ]]; then
  server_pid="$(/usr/sbin/lsof -nP -t -a -iTCP:4173 -sTCP:LISTEN 2>/dev/null | /usr/bin/head -n 1)"
  if [[ -n "$server_pid" ]]; then
    server_cwd="$(/usr/sbin/lsof -a -p "$server_pid" -d cwd -Fn 2>/dev/null | /usr/bin/sed -n 's/^n//p')"
    if [[ "$server_cwd" == "$APP_DIR" ]]; then
      cwd_verified=1
    else
      server_pid=""
    fi
  fi
fi

if [[ -z "$server_pid" ]] || ! is_pulsepath "$server_pid" "$cwd_verified"; then
  /bin/rm -f "$PID_FILE"
  echo "Pulsepath is not running."
  sleep 1
  exit 0
fi

if kill -0 "$server_pid" 2>/dev/null; then
  kill "$server_pid"
  for attempt in {1..20}; do
    kill -0 "$server_pid" 2>/dev/null || break
    sleep 0.1
  done
fi

rm -f "$PID_FILE" "$RUNTIME_DIR/token"
echo "Pulsepath stopped."
sleep 1
