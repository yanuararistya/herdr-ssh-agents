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
: "${HERDR_PLUGIN_STATE_DIR:?}" "${HERDR_PLUGIN_ROOT:?}"

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

screen_of() { # <pane>
  "$herdr" pane read "$1" --source visible --lines 12 2>/dev/null
}

# The box says an agent runs somewhere; the screen says whether it runs
# HERE. Without this, ssh-ing to a machine where anyone -- another
# session, another user, a cron job -- happens to be running an agent
# claims your shell pane for it.
#
# This asks whether the pane is showing an agent, not whether it is
# showing a shell. The first version asked the opposite, matching a
# prompt ending in $ or #, and so read every prompt style it did not
# know about as "must be an agent then" -- a starship prompt ending in
# ❯ was enough to claim a bare shell. There is no finite list of prompts;
# there is a finite list of agents.
#
# Failing closed is the point: an agent whose TUI is not recognised goes
# unlisted, which is a missing row rather than a wrong one. A wrong one
# means something may type into a shell, where a line is executed rather
# than read. Extend with SSH_AGENTS_MARKERS.
markers=${SSH_AGENTS_MARKERS:-esc to interrupt|for shortcuts|for agents|Claude Code|OpenAI Codex|⏎ send}
screen_has_agent() { # <screen-text>
  printf '%s' "$1" | grep -qE "$markers"
}

# Coarse, and deliberately so: the far end's own screen is the only
# liveness signal that crosses without installing something there. herdr
# refines it from the same content once the agent is identified.
screen_state() { # <screen-text>
  case $1 in
  *'esc to interrupt'*) echo working ;;
  *) echo idle ;;
  esac
}

now_ns() { python3 -c 'import time; print(time.time_ns())'; }

claim() { # <pane> <label> <state>
  "$herdr" pane report-agent-session "$1" --source "$source_id" --agent "$2" \
    --agent-session-id "ssh-$1" --seq "$(now_ns)" >/dev/null 2>&1
  "$herdr" pane report-agent "$1" --source "$source_id" --agent "$2" \
    --state "$3" --seq "$(now_ns)" >/dev/null 2>&1
}

# Releasing withdraws our claim, which is not the same as retiring the
# row: herdr keeps the pane's agent authority, and a nameless entry
# survives the release. Only the socket API clears that -- there is no
# CLI verb for it.
clear_authority() { # <pane>
  [ -n "${HERDR_SOCKET_PATH:-}" ] || return 0
  SA_PANE="$1" python3 -c '
import json, os, socket
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(5)
    s.connect(os.environ["HERDR_SOCKET_PATH"])
    s.sendall((json.dumps({"id": "sa-clear", "method": "pane.clear_agent_authority",
                           "params": {"pane_id": os.environ["SA_PANE"]}}) + "\n").encode())
    s.recv(4096)
except Exception:
    pass
' 2>/dev/null || true
}

# A claim outlives nothing: a pane that stopped being an ssh session, or
# whose agent exited, must not keep an entry in the sidebar that nothing
# is behind.
retract() { # <pane>
  f="$run/$(printf '%s' "$1" | tr ':' '_')"
  [ -f "$f" ] || return 0
  "$herdr" pane release-agent "$1" --source "$source_id" \
    --agent "$(cat "$f")" --seq "$(now_ns)" >/dev/null 2>&1
  clear_authority "$1"
  rm -f "$f"
  log "released $1"
}

# Everything we claimed, given up at once. Called on the way out, so a
# stop leaves no row behind that nothing is behind.
retract_all() {
  for f in "$run"/*; do
    [ -f "$f" ] || continue
    retract "$(basename "$f" | tr '_' ':')"
  done
}

# A reporter that is killed, disabled or uninstalled would otherwise
# leave its claims standing forever -- herdr persists them, and nothing
# else knows they were ours. pkill sends TERM, so this covers the way
# people actually stop it.
trap 'retract_all; exit 0' TERM INT HUP

log "watching ssh panes"
while :; do
  # Uninstalling a plugin removes its files and signals nothing, so a
  # reporter from a plugin that no longer exists would keep reporting
  # into herdr forever. Notice, give the claims back, and stop.
  if [ ! -f "$HERDR_PLUGIN_ROOT/herdr-plugin.toml" ]; then
    log "plugin root is gone; releasing and exiting"
    retract_all
    exit 0
  fi
  seen=""
  for pane in $(panes); do
    seen="$seen $pane"
    f="$run/$(printf '%s' "$pane" | tr ':' '_')"
    host=$(ssh_dest "$pane")
    if [ -z "$host" ]; then retract "$pane"; continue; fi
    label=$(remote_agent "$host")
    if [ -z "$label" ]; then retract "$pane"; continue; fi
    # An agent exists on that box, but this pane may be sitting at a
    # shell -- someone else's session, or one you exited. Only claim a
    # pane that is actually showing one.
    screen=$(screen_of "$pane")
    if ! screen_has_agent "$screen"; then retract "$pane"; continue; fi
    [ -f "$f" ] || log "claiming $pane -> $label on $host"
    printf '%s\n' "$label" >"$f"
    claim "$pane" "$label" "$(screen_state "$screen")"
  done
  # Panes herdr no longer has at all.
  for f in "$run"/*; do
    [ -f "$f" ] || continue
    p=$(basename "$f" | tr '_' ':')
    case " $seen " in *" $p "*) ;; *) retract "$p" ;; esac
  done
  sleep "$interval"
done
