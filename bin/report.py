#!/usr/bin/env python3
"""Report agents running behind ssh panes into herdr's agents sidebar.

herdr identifies a pane's agent from the pane's local foreground process.
For a pane running `ssh host` that is the transport, not the agent, so an
agent on the far end is invisible (herdrdev/herdr#1170). The report API
never required the reporter to *be* the agent: this asks the far end what
could be running and lets the pane's own rendering decide what is.

The rendering is judged with herdr's published agent-detection manifests
-- the same data herdr evaluates for local panes, fetched and refreshed
by herdr itself into its state directory. The reporter carries no marker
vocabulary of its own: when a TUI redesign updates herdr's detection
rules, it updates ours on the next cycle.

Fail closed, always: an unrecognised TUI goes unlisted -- a missing row,
never a claim on a live shell where an injected line would be executed.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import tomllib
import urllib.request

STATE = os.environ.get("HERDR_PLUGIN_STATE_DIR")
ROOT = os.environ.get("HERDR_PLUGIN_ROOT")
HERDR = os.environ.get("HERDR_BIN_PATH", "herdr")
INTERVAL = float(os.environ.get("SSH_AGENTS_INTERVAL", "5"))
SOURCE_ID = "ssh-agents"
SCREEN_LINES = 40

# Process names to look for on the far end, in preference order. The order
# only breaks ties when one screen satisfies several manifests, which the
# per-agent rules make rare. Overridable, but the default covers every
# agent herdr itself can name.
DEFAULT_NAMES = (
    "claude codex gemini cursor cursor-agent opencode droid amp grok pi "
    "cline copilot kimi kiro hermes kilo qodercli maki devin agy mastracode omp"
)

CATALOG_URL = "https://herdr.dev/agent-detection/index.toml"
FETCH_CAP = 256 * 1024


def log(*parts):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), *parts, flush=True)


# --- herdr API ---------------------------------------------------------------


def herdr_json(*args):
    try:
        out = subprocess.run(
            [HERDR, *args], capture_output=True, text=True, timeout=15
        ).stdout
        return json.loads(out) if out.strip() else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def pane_ids():
    data = herdr_json("pane", "list") or {}
    panes = data.get("result", {}).get("panes", [])
    return [p["pane_id"] for p in panes if "pane_id" in p]


def pane_title(pane):
    data = herdr_json("pane", "get", pane) or {}
    return data.get("result", {}).get("pane", {}).get("terminal_title") or ""


def pane_screen(pane):
    try:
        return subprocess.run(
            [HERDR, "pane", "read", pane, "--source", "visible", "--lines", str(SCREEN_LINES)],
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


# The pane's ssh destination, or None.
#
# Only the foreground job's own ssh counts. A ProxyJump child appears in
# the same job as `ssh -W [host]:22 jump` and names the jump host, not
# where you are. Options that take a value are skipped so `-p 2222 host`
# and `-J jump host` do not hand back the option's argument.
SSH_VALOPTS = set("bcDEeFIiJLlmOopQRSWw")


def ssh_dest(pane):
    data = herdr_json("pane", "process-info", "--pane", pane) or {}
    procs = (
        data.get("result", {}).get("process_info", {}).get("foreground_processes", [])
    )
    for proc in procs:
        argv = proc.get("argv") or []
        if not argv or proc.get("argv0") != "ssh" or "-W" in argv:
            continue
        it = iter(argv[1:])
        for arg in it:
            if arg == "--":
                arg = next(it, None)
            elif arg.startswith("-"):
                if len(arg) == 2 and arg[1] in SSH_VALOPTS:
                    next(it, None)
                continue
            if arg:
                return arg
    return None


# --- remote probe ------------------------------------------------------------
#
# One ssh handshake per host, reused via ControlMaster. The master is ours
# and short-lived, so it cannot outlive the reporter by much.
#
# The probe answers two questions. The strong one: which agent process
# serves WHICH PANE. herdr exports the pane's identity as LC_HERDR_PANE,
# ssh forwards LC_* by platform default -- end to end, through jump
# hosts, since it is session protocol rather than a TCP fact -- and
# every process of that remote session inherits it. A candidate whose
# environment names the pane and whose process group is its terminal's
# foreground group (pgrp == tpgid, the literal local rule evaluated
# remotely) IS that pane's agent, the way a local foreground process
# is: identity by process table, not by inference, for agents that
# announce nothing. Nothing is configured anywhere for this; a hardened
# sshd that strips env simply leaves the weak answer.
#
# The weak one, for sessions without the env: which agents exist on the
# box at all -- candidates for the evidence machinery below.
#
# HERDR_AGENT in a candidate's environment is herdr's own opt-in identity
# marker; a candidate that declares a label is believed over its process
# name, which covers agents launched through wrappers pgrep cannot see
# through.


def probe(host, names):
    """Returns (anchored, candidates).

    anchored: pane_id -> agent label, for remote foreground processes
    that inherited this herdr's pane identity. Ambiguity (two labels
    claiming one pane) discards the anchor for that pane: fail closed,
    the evidence machinery still runs.
    candidates: agent labels present on the box, in preference order,
    for panes the anchor cannot answer.
    """
    pattern = "|".join(names)
    cmd = (
        f"for p in $(pgrep -x '{pattern}' 2>/dev/null); do "
        f'set -- $(cut -d")" -f2- /proc/$p/stat 2>/dev/null); '
        f'[ -n "${{6:-}}" ] || continue; '
        f'fg=0; [ "$3" = "$6" ] && fg=1; '
        f"pane=$(tr '\\0' '\\n' </proc/$p/environ 2>/dev/null | sed -n 's/^LC_HERDR_PANE=//p' | head -1); "
        f"agent=$(tr '\\0' '\\n' </proc/$p/environ 2>/dev/null | sed -n 's/^HERDR_AGENT=//p' | head -1); "
        f"name=$(cat /proc/$p/comm 2>/dev/null); "
        f'printf "P|%s|%s|%s|%s\\n" "$name" "$fg" "$pane" "$agent"; '
        f"done"
    )
    try:
        out = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={STATE}/ssh-%h",
                "-o", "ControlPersist=120",
                host,
                cmd,
            ],
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return {}, []
    found = set()
    pane_labels = {}
    for line in out.splitlines():
        if not line.startswith("P|"):
            continue
        parts = line.split("|")
        if len(parts) != 5:
            continue
        _, name, fg, pane, declared = parts
        label = (declared or name).strip().lower()
        if not label:
            continue
        found.add(label)
        if pane and fg == "1":
            pane_labels.setdefault(pane, set()).add(label)
    anchored = {
        pane: labels.pop()
        for pane, labels in pane_labels.items()
        if len(labels) == 1
    }
    candidates = [name for name in names if name in found] + sorted(
        name for name in found if name not in names
    )
    return anchored, candidates


# --- manifests ---------------------------------------------------------------
#
# herdr keeps its fetched manifests in <state_dir>/agent-detection/remote.
# Reading that cache means judging screens with exactly the rules the local
# herdr judges its own panes with, at zero fetch cost. The fetch fallback
# exists for a host where herdr has not populated the cache yet.


def herdr_state_dirs():
    xdg = os.environ.get("XDG_STATE_HOME")
    home = os.path.expanduser("~")
    return [d for d in (
        os.environ.get("SSH_AGENTS_MANIFEST_DIR"),
        os.path.join(xdg, "herdr") if xdg else None,
        os.path.join(home, ".local", "state", "herdr"),
        os.path.join(home, "Library", "Application Support", "herdr"),
    ) if d]


def manifest_dir():
    for state_dir in herdr_state_dirs():
        remote = os.path.join(state_dir, "agent-detection", "remote")
        if os.path.isdir(remote) and any(
            name.endswith(".toml") for name in os.listdir(remote)
        ):
            return remote
    return None


def fetch_manifests():
    dest = os.path.join(STATE, "agent-detection")
    os.makedirs(dest, exist_ok=True)
    try:
        with urllib.request.urlopen(CATALOG_URL, timeout=15) as resp:
            catalog = tomllib.loads(resp.read(FETCH_CAP).decode())
        for entry in catalog.get("agents", []):
            path = entry.get("path", "")
            if not path or path.startswith(("/", "..")) or "://" in path:
                continue
            url = CATALOG_URL.rsplit("/", 1)[0] + "/" + path
            with urllib.request.urlopen(url, timeout=15) as resp:
                body = resp.read(FETCH_CAP)
            with open(os.path.join(dest, os.path.basename(path)), "wb") as f:
                f.write(body)
        log("fetched manifests from", CATALOG_URL)
        return dest
    except Exception as err:  # noqa: BLE001 -- any failure means no vocabulary
        log("manifest fetch failed:", err)
        return None


class Manifests:
    def __init__(self):
        self.dir = None
        self.stamp = None
        self.by_label = {}
        self.shared_atoms = set()

    def load(self):
        directory = manifest_dir()
        if directory is None and self.dir is None:
            directory = fetch_manifests()
        if directory is None:
            directory = self.dir
        if directory is None:
            return
        try:
            names = sorted(
                n for n in os.listdir(directory) if n.endswith(".toml")
            )
            stamp = tuple(
                (n, os.stat(os.path.join(directory, n)).st_mtime) for n in names
            )
        except OSError:
            return
        if directory == self.dir and stamp == self.stamp:
            return
        by_label = {}
        entries = []
        for name in names:
            try:
                with open(os.path.join(directory, name), "rb") as f:
                    manifest = tomllib.load(f)
            except (OSError, tomllib.TOMLDecodeError) as err:
                log("skipping manifest", name, "--", err)
                continue
            rules = [r for r in manifest.get("rules", []) if compile_rule(r)]
            if not rules:
                continue
            entry = {"id": manifest.get("id", ""), "rules": rules}
            entries.append(entry)
            for label in [manifest.get("id", "")] + list(manifest.get("aliases", [])):
                if label:
                    by_label[label.lower()] = entry
        self.shared_atoms = mark_shared_atoms(entries)
        self.dir, self.stamp, self.by_label = directory, stamp, by_label
        log(f"loaded {len(by_label)} agent labels from {directory}")

    def for_label(self, label):
        return self.by_label.get(label.lower())


# --- rule evaluation ---------------------------------------------------------
#
# A faithful port of herdr's gate semantics (src/detect/manifest.rs):
# within a gate every listed condition must hold; `any` needs one nested
# gate, `not` refuses all; the winning rule is the highest priority with
# earlier rules keeping ties. Two deliberate divergences, both fail-closed:
# regions that depend on herdr's internal prompt-marker machinery are
# approximated by the whole screen, and osc_progress (which the pane API
# does not expose) evaluates against the empty string -- a rule needing it
# simply never matches.

_EXACT_REGIONS = ("osc_title", "osc_progress", "whole_recent")


def _rust_regex(pattern):
    return re.sub(
        r"\\x\{([0-9a-fA-F]{1,6})\}",
        lambda m: "\\U%08x" % int(m.group(1), 16),
        pattern,
    )


def _compile_gate(gate):
    try:
        return {
            "contains": [(c, c.lower()) for c in gate.get("contains", [])],
            "regex": [
                (p, re.compile(_rust_regex(p))) for p in gate.get("regex", [])
            ],
            "line_regex": [
                (p, re.compile(_rust_regex(p))) for p in gate.get("line_regex", [])
            ],
            "all": [_compile_gate(g) for g in gate.get("all", [])],
            "any": [_compile_gate(g) for g in gate.get("any", [])],
            "not": [_compile_gate(g) for g in gate.get("not", [])],
        }
    except (re.error, AttributeError, TypeError):
        return None


# Manifests are state classifiers that assume identity is already known:
# herdr runs them only after the process table names the agent. Some rules
# are therefore deliberately generic -- codex's "any non-spinner title
# means idle" is sound in that world and meaningless as evidence that the
# pane IS codex. Presence needs evidence a plain shell could not produce,
# so every rule is tested against null fixtures at load time; a rule that
# matches a fixture may still classify state but can never establish
# presence. This is the old hand-rolled-marker discipline, applied
# mechanically to upstream's vocabulary.
_NULL_SCREEN = "dev@host:~$ ls\nsrc README.md\ndev@host:~$\n"
_NULL_FIXTURES = (
    ("", ""),
    (_NULL_SCREEN, "user@host: ~"),
    (_NULL_SCREEN, "-zsh"),
    (_NULL_SCREEN, "bash"),
)


def compile_rule(rule):
    compiled = _compile_gate(rule)
    if compiled is None:
        return False
    rule["_gate"] = compiled
    rule["_distinctive"] = not any(
        _gate_matches(
            compiled,
            text := _region(rule.get("region", "whole_recent"), screen, title),
            text.lower(),
        )
        for screen, title in _NULL_FIXTURES
    )
    return True


# Agents borrow each other's vocabulary: "esc to interrupt" appears in six
# manifests and the braille-spinner title in three, so a match on either
# says "some agent is here", not which. Sharing is counted per atom -- each
# individual contains-string or pattern, across every manifest -- because
# the same borrowed phrase arrives wrapped in different gate shapes.
# Evidence built only from shared atoms cannot pick an agent from several
# candidates; it can hold a claim already made (state classification is
# what these rules are for upstream) and it can satisfy a lone candidate.
def _gate_atoms(gate):
    atoms = set()
    for kind in ("contains", "regex", "line_regex"):
        for pattern in gate.get(kind, []):
            atoms.add((kind, pattern))
    for nested_kind in ("all", "any", "not"):
        for nested in gate.get(nested_kind, []):
            atoms |= _gate_atoms(nested)
    return atoms


def mark_shared_atoms(entries):
    owners = {}
    for entry in entries:
        for rule in entry["rules"]:
            for atom in _gate_atoms(rule):
                owners.setdefault(atom, set()).add(entry["id"])
    return {atom for atom, who in owners.items() if len(who) > 1}


def _gate_matches(gate, text, lower_text, shared=frozenset(), unique=False):
    # In unique mode an atom drawn from shared vocabulary counts as failed,
    # so the gate passes only on evidence that names this agent alone.
    # `not` exclusions always evaluate in full -- they are about what is on
    # the screen, not whose vocabulary describes it.
    def ok(kind, pattern, hit):
        return hit and not (unique and (kind, pattern) in shared)

    if any(
        not ok("contains", orig, low in lower_text)
        for orig, low in gate["contains"]
    ):
        return False
    if any(
        not ok("regex", pat, bool(compiled.search(text)))
        for pat, compiled in gate["regex"]
    ):
        return False
    lines = text.splitlines()
    if any(
        not ok("line_regex", pat, any(compiled.search(line) for line in lines))
        for pat, compiled in gate["line_regex"]
    ):
        return False
    if any(
        not _gate_matches(g, text, lower_text, shared, unique)
        for g in gate["all"]
    ):
        return False
    if gate["any"] and not any(
        _gate_matches(g, text, lower_text, shared, unique) for g in gate["any"]
    ):
        return False
    if any(_gate_matches(g, text, lower_text) for g in gate["not"]):
        return False
    return True


def _region(spec, screen, title):
    spec = spec.strip()
    if spec == "osc_title":
        return title
    if spec == "osc_progress":
        return ""
    lines = screen.splitlines()
    for prefix in ("bottom_lines", "bottom_non_empty_lines"):
        m = re.fullmatch(re.escape(prefix) + r"\((\d+)\)", spec)
        if not m:
            continue
        count = int(m.group(1))
        if prefix == "bottom_lines":
            start = max(0, len(lines) - count)
        else:
            non_empty = [i for i, line in enumerate(lines) if line.strip()]
            if not non_empty:
                return ""
            start = non_empty[-count] if count <= len(non_empty) else non_empty[0]
        return "\n".join(lines[start:])
    m = re.fullmatch(r"top_non_empty_lines\((\d+)\)", spec)
    if m:
        non_empty = [line for line in lines if line.strip()]
        return "\n".join(non_empty[: int(m.group(1))])
    if spec == "last_non_empty_above_prompt_box":
        non_empty = [line for line in lines if line.strip()]
        return non_empty[-1] if non_empty else ""
    # whole_recent and every prompt-marker region we cannot reproduce.
    return screen


def evaluate(entry, screen, title, shared_atoms=frozenset()):
    """One agent's manifest against one pane.

    Returns (unique_present, present, state): `present` is distinctive
    evidence a shell could not produce; `unique_present` additionally
    survives with every shared atom removed, so it names this agent alone.
    """
    winner = None
    present = False
    unique_present = False
    for rule in entry["rules"]:
        text = _region(rule.get("region", "whole_recent"), screen, title)
        lower = text.lower()
        if not _gate_matches(rule["_gate"], text, lower):
            continue
        state = rule.get("state", "unknown")
        if rule["_distinctive"] and (
            (rule.get("visible_idle") and state == "idle")
            or (rule.get("visible_working") and state == "working")
            or (rule.get("visible_blocker") and state == "blocked")
        ):
            present = True
            if _gate_matches(rule["_gate"], text, lower, shared_atoms, unique=True):
                unique_present = True
        if winner is None or rule.get("priority", 0) > winner.get("priority", 0):
            winner = rule
    state = winner.get("state", "unknown") if winner else "unknown"
    return unique_present, present, state


# --- claims ------------------------------------------------------------------


def now_ns():
    return time.time_ns()


def claim_path(pane):
    return os.path.join(STATE, "claimed", pane.replace(":", "_"))


def claim(pane, label, state):
    subprocess.run(
        [HERDR, "pane", "report-agent-session", pane, "--source", SOURCE_ID,
         "--agent", label, "--agent-session-id", f"ssh-{pane}",
         "--seq", str(now_ns())],
        capture_output=True, timeout=15,
    )
    subprocess.run(
        [HERDR, "pane", "report-agent", pane, "--source", SOURCE_ID,
         "--agent", label, "--state", state, "--seq", str(now_ns())],
        capture_output=True, timeout=15,
    )


# Releasing withdraws our claim, which is not the same as retiring the row:
# herdr keeps the pane's agent authority, and a nameless entry survives the
# release. Only the socket API clears that -- there is no CLI verb for it.
def clear_authority(pane):
    path = os.environ.get("HERDR_SOCKET_PATH")
    if not path:
        return
    try:
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(5)
            sock.connect(path)
            sock.sendall(
                (json.dumps({
                    "id": "sa-clear",
                    "method": "pane.clear_agent_authority",
                    "params": {"pane_id": pane},
                }) + "\n").encode()
            )
            sock.recv(4096)
    except OSError:
        pass


def read_claim(pane):
    """Returns (label, host) recorded for the pane, or (None, None)."""
    try:
        with open(claim_path(pane)) as f:
            parts = f.read().split()
    except OSError:
        return None, None
    if not parts:
        return None, None
    return parts[0], parts[1] if len(parts) > 1 else None


# forget=False is the shutdown path: the rows are released so a stopped
# reporter leaves nothing standing in herdr, but the memory of what was
# proven stays on disk. Retention is anchored to the REMOTE process, and
# that process did not restart just because the reporter did -- without
# the memory, every restart would drop each idle agent until its next
# turn produced fresh evidence. A real departure forgets.
def retract(pane, forget=True):
    label, _ = read_claim(pane)
    if label is None:
        return
    subprocess.run(
        [HERDR, "pane", "release-agent", pane, "--source", SOURCE_ID,
         "--agent", label, "--seq", str(now_ns())],
        capture_output=True, timeout=15,
    )
    clear_authority(pane)
    if forget:
        os.unlink(claim_path(pane))
    log("released", pane)


def retract_all():
    claimed = os.path.join(STATE, "claimed")
    for name in os.listdir(claimed) if os.path.isdir(claimed) else []:
        retract(name.replace("_", ":"), forget=False)


# --- main --------------------------------------------------------------------


def cycle(manifests, names, dry_run=False):
    manifests.load()
    seen = set()
    for pane in pane_ids():
        seen.add(pane)
        host = ssh_dest(pane)
        if not host:
            dry_run or retract(pane)
            continue
        anchored, candidates = probe(host, names)
        if not candidates:
            dry_run or retract(pane)
            continue
        # An agent exists on that box, but this pane may be at a shell --
        # someone else's session, or one you exited -- and a box running
        # two agents cannot say which is here. Acquiring a claim takes
        # evidence that names one candidate alone (or any distinctive
        # evidence, when the process table left a single candidate).
        #
        # Holding a claim already made takes no screen evidence at all,
        # only the process still existing -- which is herdr's own model,
        # acquisition by anchor and retention by process lifetime, and it
        # covers the state manifests are silent about: an agent's idle
        # screen never needed evidence upstream (the process anchor
        # answers there), so idle codex matches nothing and must not
        # flap out of the sidebar between turns. A retained claim whose
        # screen matches no rule is idle for the same reason herdr's
        # fallback is: known agent, nothing to report.
        screen = pane_screen(pane)
        title = pane_title(pane)
        held, held_host = read_claim(pane)
        if held_host != host:
            held = None
        chosen = None
        # The strong answer first: a remote foreground process that
        # inherited this pane's identity IS this pane's agent -- the
        # process table says so, the way it says so locally, and the
        # agent said nothing. Identity by observation; the manifests do
        # their upstream job of classifying state, with herdr's own
        # idle fallback when a quiet screen matches nothing.
        anchor = anchored.get(pane)
        if anchor:
            entry = manifests.for_label(anchor)
            if entry is not None:
                _, _, state = evaluate(entry, screen, title, manifests.shared_atoms)
                chosen = (entry["id"], state if state != "unknown" else "idle")
        sole = len(candidates) == 1
        for label in [] if chosen else candidates:
            entry = manifests.for_label(label)
            if entry is None:
                continue
            unique_present, present, state = evaluate(
                entry, screen, title, manifests.shared_atoms
            )
            if unique_present or (sole and present):
                chosen = (entry["id"], state)
                break
        if chosen is None and held is not None:
            for label in candidates:
                entry = manifests.for_label(label)
                if entry is None or entry["id"] != held:
                    continue
                _, _, state = evaluate(entry, screen, title, manifests.shared_atoms)
                chosen = (held, state if state != "unknown" else "idle")
                break
        if dry_run:
            log(f"dry-run: {pane} host={host} candidates={candidates} -> {chosen}")
            continue
        if chosen is None:
            retract(pane)
            continue
        label, state = chosen
        path = claim_path(pane)
        if read_claim(pane) != (label, host):
            log(f"claiming {pane} -> {label} on {host}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(f"{label} {host}\n")
        claim(pane, label, state)
    if dry_run:
        return
    # Panes herdr no longer has at all.
    claimed = os.path.join(STATE, "claimed")
    for name in os.listdir(claimed) if os.path.isdir(claimed) else []:
        pane = name.replace("_", ":")
        if pane not in seen:
            retract(pane)


def main():
    if not STATE or not ROOT:
        sys.exit("HERDR_PLUGIN_STATE_DIR and HERDR_PLUGIN_ROOT are required")
    dry_run = "--dry-run" in sys.argv
    once = dry_run or "--once" in sys.argv
    os.makedirs(os.path.join(STATE, "claimed"), exist_ok=True)
    names = os.environ.get("SSH_AGENTS_NAMES", DEFAULT_NAMES).split()
    manifests = Manifests()

    # A reporter that is killed, disabled or uninstalled would otherwise
    # leave its claims standing forever -- herdr persists them, and nothing
    # else knows they were ours.
    def bail(signum, frame):
        retract_all()
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, bail)

    log("watching ssh panes")
    while True:
        # Uninstalling a plugin removes its files and signals nothing, so a
        # reporter from a plugin that no longer exists would keep reporting
        # into herdr forever. Notice, give the claims back, and stop.
        if not os.path.isfile(os.path.join(ROOT, "herdr-plugin.toml")):
            log("plugin root is gone; releasing and exiting")
            retract_all()
            return
        cycle(manifests, names, dry_run)
        if once:
            return
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
