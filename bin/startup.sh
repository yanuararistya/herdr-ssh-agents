#!/bin/sh
# Start one reporter, replacing any left from a previous run. herdr runs
# this when its server starts; the restart action runs it again.
set -u
: "${HERDR_PLUGIN_ROOT:?}" "${HERDR_PLUGIN_STATE_DIR:?}"
pidf="$HERDR_PLUGIN_STATE_DIR/reporter.pid"
if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
  kill "$(cat "$pidf")" 2>/dev/null
  sleep 1
fi
if command -v setsid >/dev/null 2>&1; then
  setsid sh "$HERDR_PLUGIN_ROOT/bin/report.sh" >>"$HERDR_PLUGIN_STATE_DIR/report.log" 2>&1 &
else
  sh "$HERDR_PLUGIN_ROOT/bin/report.sh" >>"$HERDR_PLUGIN_STATE_DIR/report.log" 2>&1 &
fi
echo $! >"$pidf"
echo "ssh-agents: reporter started (pid $!)"
