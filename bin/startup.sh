#!/bin/sh
# Start one reporter, replacing any left from a previous run. herdr runs
# this when its server starts; the restart action runs it again.
#
# The reporter needs python3.11+ for tomllib (herdr's agent-detection
# manifests are TOML). macOS system python is older, so probe for a
# capable interpreter rather than trusting `python3`.
set -u
: "${HERDR_PLUGIN_ROOT:?}" "${HERDR_PLUGIN_STATE_DIR:?}"

python=""
for candidate in python3 python3.13 python3.12 python3.11 \
  /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.13 \
  /opt/homebrew/bin/python3.12 /usr/local/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1 &&
    "$candidate" -c 'import tomllib' 2>/dev/null; then
    python=$candidate
    break
  fi
done
if [ -z "$python" ]; then
  echo "ssh-agents: no python3.11+ with tomllib found; not starting" >&2
  exit 1
fi

pidf="$HERDR_PLUGIN_STATE_DIR/reporter.pid"
if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
  kill "$(cat "$pidf")" 2>/dev/null
  sleep 1
fi
if command -v setsid >/dev/null 2>&1; then
  setsid "$python" "$HERDR_PLUGIN_ROOT/bin/report.py" >>"$HERDR_PLUGIN_STATE_DIR/report.log" 2>&1 &
else
  "$python" "$HERDR_PLUGIN_ROOT/bin/report.py" >>"$HERDR_PLUGIN_STATE_DIR/report.log" 2>&1 &
fi
echo $! >"$pidf"
echo "ssh-agents: reporter started (pid $!, $python)"
