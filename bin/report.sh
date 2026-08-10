#!/bin/sh
# Report agents running behind ssh panes into herdr's agents sidebar.
#
# herdr identifies an agent from the pane's foreground process. For a
# pane running `ssh host` that is the transport, not the agent, so an
# agent started on the far end is invisible (herdrdev/herdr#1170). Its
# other identity path, the hook report, arrives on a unix socket on this
# machine -- which the remote agent cannot reach.
#
# But the report API never required the reporter to *be* the agent. This
# asks the far end what it is running and reports on the pane's behalf,
# using the same shipped contract the local hooks use. No patched herdr,
# nothing installed on the remote host.
set -u
: "${HERDR_PLUGIN_STATE_DIR:?}"

herdr=${HERDR_BIN_PATH:-herdr}
state="$HERDR_PLUGIN_STATE_DIR"
run="$state/claimed"
mkdir -p "$run"
interval=${SSH_AGENTS_INTERVAL:-5}
source_id=ssh-agents

# Process names to look for on the far end, in preference order. A box
# running two is unusual; the order decides which one the pane is said to
# be, and is only consulted when more than one is present.
agents=${SSH_AGENTS_NAMES:-claude codex gemini cursor opencode droid amp}

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

# One ssh handshake per host, reused. A probe over a fresh connection
# spends over a second in setup and hundredths on the question; over a
# reused one it is all question. The master is ours and short-lived, so
# it cannot outlive the plugin by much.
ssh_probe() { # <host> <command...>
  ssh -o BatchMode=yes -o ConnectTimeout=5 \
    -o ControlMaster=auto -o ControlPath="$state/ssh-%h" \
    -o ControlPersist=120 "$@"
}

panes() {
  "$herdr" pane list 2>/dev/null |
    tr ',' '\n' | sed -n 's/.*"pane_id":"\([^"]*\)".*/\1/p'
}

# The pane's ssh destination, or nothing.
#
# Only the foreground job's own ssh counts. A ProxyJump child appears in
# the same job as `ssh -W [host]:22 jump` and names the jump host, not
# where you are -- reporting that would probe the wrong machine. Options
# that take a value are skipped so `-p 2222 host` and `-J jump host` do
# not hand back the option's argument as the destination.
ssh_dest() { # <pane>
  "$herdr" pane process-info --pane "$1" 2>/dev/null | python3 -c '
import json, sys
VALOPTS = set("bcDEeFIiJLlmOopQRSWw")
try:
    procs = json.load(sys.stdin)["result"]["process_info"]["foreground_processes"]
except Exception:
    sys.exit(0)
for p in procs:
    argv = p.get("argv") or []
    if not argv or p.get("argv0") != "ssh" or "-W" in argv:
        continue
    it = iter(argv[1:])
    for a in it:
        if a == "--":
            a = next(it, None)
        elif a.startswith("-"):
            if len(a) == 2 and a[1] in VALOPTS:
                next(it, None)
            continue
        if a:
            print(a)
            sys.exit(0)
'
}

# Which agent is running over there, if any. One pgrep rather than one
# per name: over a reused connection the round trip is nearly free but
# each remote process spawn is not, and this runs every cycle for every
# ssh pane whether or not anything is there.
remote_agent() { # <host>
  pattern=$(printf '%s' "$agents" | tr ' ' '|')
  running=$(ssh_probe "$1" "pgrep -lx '$pattern'" 2>/dev/null | awk '{print $2}')
  for a in $agents; do
    printf '%s\n' "$running" | grep -qx "$a" && { echo "$a"; return; }
  done
}

# Coarse, and deliberately so: the far end's own screen is the only
# liveness signal that crosses without installing something there. herdr
# refines it from the same content once the agent is identified.
screen_state() { # <pane>
  if "$herdr" pane read "$1" --source visible --lines 6 2>/dev/null |
    grep -q 'esc to interrupt'; then echo working; else echo idle; fi
}

now_ns() { python3 -c 'import time; print(time.time_ns())'; }

claim() { # <pane> <label> <state>
  "$herdr" pane report-agent-session "$1" --source "$source_id" --agent "$2" \
    --agent-session-id "ssh-$1" --seq "$(now_ns)" >/dev/null 2>&1
  "$herdr" pane report-agent "$1" --source "$source_id" --agent "$2" \
    --state "$3" --seq "$(now_ns)" >/dev/null 2>&1
}

# A claim outlives nothing: a pane that stopped being an ssh session, or
# whose agent exited, must not keep an entry in the sidebar that nothing
# is behind.
retract() { # <pane>
  f="$run/$(printf '%s' "$1" | tr ':' '_')"
  [ -f "$f" ] || return 0
  "$herdr" pane release-agent "$1" --source "$source_id" \
    --agent "$(cat "$f")" --seq "$(now_ns)" >/dev/null 2>&1
  rm -f "$f"
  log "released $1"
}

log "watching ssh panes"
while :; do
  seen=""
  for pane in $(panes); do
    seen="$seen $pane"
    f="$run/$(printf '%s' "$pane" | tr ':' '_')"
    host=$(ssh_dest "$pane")
    if [ -z "$host" ]; then retract "$pane"; continue; fi
    label=$(remote_agent "$host")
    if [ -z "$label" ]; then retract "$pane"; continue; fi
    [ -f "$f" ] || log "claiming $pane -> $label on $host"
    printf '%s\n' "$label" >"$f"
    claim "$pane" "$label" "$(screen_state "$pane")"
  done
  # Panes herdr no longer has at all.
  for f in "$run"/*; do
    [ -f "$f" ] || continue
    p=$(basename "$f" | tr '_' ':')
    case " $seen " in *" $p "*) ;; *) retract "$p" ;; esac
  done
  sleep "$interval"
done
