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

# Every agent running over there, in preference order -- not just the
# first. A box can run several, and which one *this pane* is showing is
# not a question the remote process table can answer. It narrows the
# candidates; the pane picks among them.
remote_agents() { # <host>
  pattern=$(printf '%s' "$agents" | tr ' ' '|')
  running=$(ssh_probe "$1" "pgrep -lx '$pattern'" 2>/dev/null | awk '{print $2}')
  for a in $agents; do
    printf '%s\n' "$running" | grep -qx "$a" && printf '%s ' "$a"
  done
}

pane_title() { # <pane>
  "$herdr" pane get "$1" 2>/dev/null |
    sed -n 's/.*"terminal_title":"\([^"]*\)".*/\1/p' | head -1
}

screen_of() { # <pane>
  "$herdr" pane read "$1" --source visible --lines 12 2>/dev/null
}

# The box says an agent runs somewhere; the screen says whether it runs
# HERE. Without this, ssh-ing to a machine where anyone -- another
# session, another user, a cron job -- happens to be running an agent
# claims your shell pane for it.
#
# This asks whether the pane shows *the agent the box is running*, keyed
# per agent, because pgrep already told us which one that is. A narrower
# test than one global list: codex markers are never applied to a box
# running claude, so they cannot false-positive there.
#
# Read this for what it is: a heuristic over someone else's rendering.
# It breaks on redesigns -- codex's newer TUI dropped every marker the
# first version had -- and there is no list of prompts that stays right,
# which is why the test is positive rather than negative. It fails
# closed: an unrecognised TUI goes unlisted, a missing row rather than a
# claim on a live shell where an injected line would be executed.
# The reliable answer needs the far end to announce itself; see the
# README.
markers_for() { # <agent>
  case $1 in
  claude) printf '%s' "${SSH_AGENTS_MARKERS_CLAUDE:-esc to interrupt|for shortcuts|for agents|Claude Code}" ;;
  # Primary is the persistent footer, "<model> <effort> <speed> · <cwd>".
  # The model carries a hyphen (gpt-5.6-sol), so the character after the
  # family cannot be assumed to be a digit. The composer arrow is the
  # fallback: U+203A, which is not the U+276F that starship prompts use,
  # so it does not collide with a shell.
  codex) printf '%s' "${SSH_AGENTS_MARKERS_CODEX:-(gpt|o)[-0-9][^ ]* (low|medium|high) |OpenAI Codex|^›}" ;;
  *) printf '%s' "${SSH_AGENTS_MARKERS:-esc to interrupt|for shortcuts|for agents|⏎ send}" ;;
  esac
}

# The pane's title comes from an OSC sequence the agent emits, which
# rides the pty: it crosses ssh, jump hosts and docker exec alike, and
# unlike the screen it cannot scroll away or be reflowed. Claude Code
# sets "✳ Claude Code" there. It is matched with the same vocabulary as
# the screen, so an agent whose title names it is identified even when
# its visible text gives nothing away.
shows_agent() { # <title> <screen-text> <agent>
  printf '%s\n%s' "$1" "$2" | grep -qE "$(markers_for "$3")"
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
    candidates=$(remote_agents "$host")
    if [ -z "$candidates" ]; then retract "$pane"; continue; fi
    # An agent exists on that box, but this pane may be at a shell --
    # someone else's session, or one you exited -- and a box running two
    # agents cannot say which is here. Whichever candidate the pane is
    # showing is the answer; none of them means claim nothing.
    screen=$(screen_of "$pane")
    title=$(pane_title "$pane")
    label=""
    for a in $candidates; do
      if shows_agent "$title" "$screen" "$a"; then label=$a; break; fi
    done
    if [ -z "$label" ]; then retract "$pane"; continue; fi
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
