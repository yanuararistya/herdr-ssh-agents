# herdr-ssh-agents

Agents running behind `ssh` show up in herdr's agents sidebar.

Start an agent on a remote box from a herdr pane and it never appears in
the sidebar — the pane looks like a plain shell forever
([herdrdev/herdr#1170](https://github.com/herdrdev/herdr/issues/1170)).
This plugin fixes that on stock herdr. No patched build, and nothing
installed on the remote host.

```sh
herdr plugin install yanuararistya/herdr-ssh-agents
herdr plugin action invoke ssh-agents.restart   # start it this once
```

The second line is only for the install: herdr runs a plugin's startup
command when its server starts, not when a plugin is added to a server
already running — and you install from inside a running herdr.

Needs python3.11+ somewhere on the machine running herdr (the startup
script probes for one; herdr's detection manifests are TOML).

## Why it is needed

herdr has two ways to know an agent is in a pane, and neither crosses an
ssh boundary:

- **The pane's foreground process.** Behind ssh that is the transport,
  not the agent.
- **A hook report on herdr's unix socket.** The hook runs wherever the
  agent runs, which is the far end, and the far end cannot reach a
  socket on your machine.

Its third signal, screen detection, reads the pane's content — which
*is* the remote agent's screen — but herdr consults it only after one of
the first two names the agent. Identity has to come first, and identity
is what ssh severs.

What herdr's report API never required is that the reporter *be* the
agent. So this asks the far end what could be running and reports on the
pane's behalf, using the same shipped contract the bundled hooks use:
`pane report-agent-session`, `pane report-agent`, `pane release-agent`.

## How it decides

Every few seconds, for each pane whose foreground job is `ssh`:

1. reads the destination from the pane's own process info — the ssh
   you already ran, no wrapper
2. asks that host, over a reused connection, which known agents are
   running there — all of them, since a box may run several. A remote
   process that sets `HERDR_AGENT=<label>`, herdr's own opt-in identity
   marker, is believed over its process name
3. decides which of those candidates the pane is showing, by judging its
   title and visible text against **herdr's published agent-detection
   manifests** — the same rules herdr evaluates for local panes, read
   from the cache herdr itself keeps fresh. The reporter carries no
   detection vocabulary of its own: when a TUI redesign updates herdr's
   rules, it updates ours on the next sweep, for every agent herdr knows
4. reports it, with the state the winning manifest rule names, and
   releases the claim when the evidence goes away or the pane stops
   being an ssh session

The manifests were written to classify *state* for an agent already
identified, so borrowing them for *identity* takes two mechanical
disciplines, both fail-closed:

- **Presence needs evidence a shell could not produce.** Every rule is
  tested against null fixtures (an empty pane, generic shell titles) at
  load time; a rule that matches a fixture — codex's "any non-spinner
  title means idle", say — may still classify state but can never
  establish that an agent is present.
- **Choosing among candidates needs evidence that names one agent
  alone.** Agents borrow each other's vocabulary ("esc to interrupt"
  appears in six manifests, the braille spinner title in three), so
  sharing is counted per atom across the whole corpus. Shared evidence
  can satisfy a lone candidate and can hold a claim already made —
  identity was settled when the claim was acquired, which is herdr's own
  model — but it cannot pick among several. No unique evidence, no
  claim.

Destination parsing is the fiddly part and is done properly: a
`ProxyJump` child shows up in the same job as `ssh -W [host]:22 jump`
and names the jump host rather than where you are, so it is skipped, and
options that take a value are stepped over so `ssh -p 2222 host` does
not report `2222`.

## Configuration

Environment, read at start:

- `SSH_AGENTS_INTERVAL` — seconds between sweeps (default `5`)
- `SSH_AGENTS_NAMES` — remote process names to look for, in preference
  order (default: every agent herdr can name)
- `SSH_AGENTS_MANIFEST_DIR` — override where herdr's agent-detection
  manifests are read from (default: herdr's own state directory, with a
  fetch from herdr.dev as fallback)

Actions: `ssh-agents.status` shows what it sees and claims,
`ssh-agents.restart` restarts the reporter.

## The version where nothing is guessed

Everything above is inference over rendering, because stock herdr gives
a plugin nothing better. The reliable answer is for the agent to say
what it is, in-band: an escape sequence from the agent's own hooks rides
the pty, so it crosses ssh, jump hosts and `docker exec` with no
polling and no probing at all.

`announce/` in this repo is that emitter — `herdr-announce` writes an
OSC 21337 announcement (`agent=claude;state=working;seq=…`) to the
controlling terminal, and a Claude Code hooks snippet wires it to the
agent's lifecycle. Stock herdr parses that sequence today and discards
it into a debug log; the
[`inband-agent-announcement`](https://github.com/yanuararistya/herdr/tree/inband-agent-announcement)
branch routes it into herdr's existing hook-authority machinery instead,
which also makes the agent promptable — the one thing a plugin can
never grant, since `agent prompt` re-checks the local process table.
If herdr adopts that design, this plugin retiring is the success
condition: obsolete by design.

## Limits, so they are not a surprise

- **`herdr agent prompt` still refuses these panes** on stock herdr.
  Visible is not addressable; that check is a core change (see above),
  not something a plugin can reach.
- **It polls.** A plugin cannot hook herdr's detection loop. The
  in-tree version of this does not need to.
- **A box running several agents is resolved conservatively.** If the
  pane's evidence is all shared vocabulary and no claim is held yet, the
  pane goes unlisted until something unique appears — a missing row,
  never a guess that could put a prompt into the wrong terminal.

## Provenance

Written while building [herdr-beb](https://github.com/getbeb/herdr-beb),
which needs the same discovery for a different reason — delivering
cross-machine agent mail into panes. This plugin has no dependency on
that, or on [beb](https://github.com/getbeb/beb).

## License

MIT
