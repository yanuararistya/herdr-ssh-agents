#!/bin/sh
# What the reporter currently sees and claims.
set -u
: "${HERDR_PLUGIN_STATE_DIR:?}"
pidf="$HERDR_PLUGIN_STATE_DIR/reporter.pid"
if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
  echo "reporter: running (pid $(cat "$pidf"))"
else
  echo "reporter: not running -- run the ssh-agents.restart action"
fi
echo
echo "claimed panes:"
found=""
for f in "$HERDR_PLUGIN_STATE_DIR"/claimed/*; do
  [ -f "$f" ] || continue
  found=1
  printf '  %s -> %s\n' "$(basename "$f" | tr '_' ':')" "$(cat "$f")"
done
[ -n "$found" ] || echo "  (none)"
echo
echo "recent log:"
tail -8 "$HERDR_PLUGIN_STATE_DIR/report.log" 2>/dev/null | sed 's/^/  /' || echo "  (empty)"
