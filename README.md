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

## Why it is needed

herdr has two ways to know an agent is in a pane, and neither crosses an
ssh boundary:

- **The pane's foreground process.** Behind ssh that is the transport,
  not the agent.
- **A hook report on herdr's unix socket.** The hook runs wherever the
  agent runs, which is the far end, and the far end cannot reach a
  socket on your machine.

Its third signal, screen detection, reads the pane's content — which
*is* the remote agent's screen — but it answers "what is this agent
doing", not "is there one". Identity has to come first.

What herdr's report API never required is that the reporter *be* the
agent. So this asks the far end what it is running and reports on the
pane's behalf, using the same shipped contract the bundled hooks use:
`pane report-agent-session`, `pane report-agent`, `pane release-agent`.
No new identity mechanism, no second source of truth — the same process
evidence herdr already trusts, fetched from the machine the process is
actually on.

## What it does

Every few seconds, for each pane whose foreground job is `ssh`:

1. reads the destination from the pane's own process info — the ssh
   you already ran, no wrapper
2. asks that host, over a reused connection, whether a known agent is
   running
3. reports it, and releases the claim when the agent exits or the pane
   stops being an ssh session

Destination parsing is the fiddly part and is done properly: a
`ProxyJump` child shows up in the same job as `ssh -W [host]:22 jump`
and names the jump host rather than where you are, so it is skipped, and
options that take a value are stepped over so `ssh -p 2222 host` does
not report `2222`.

## Configuration

Environment, read at start:

- `SSH_AGENTS_INTERVAL` — seconds between sweeps (default `5`)
- `SSH_AGENTS_NAMES` — process names to look for, in preference order
  (default `claude codex gemini cursor opencode droid amp`)

Actions: `ssh-agents.status` shows what it sees and claims,
`ssh-agents.restart` restarts the reporter.

## Limits, so they are not a surprise

- **`herdr agent prompt` still refuses these panes.** herdr checks the
  pane's local foreground before sending, so an agent it is happily
  displaying cannot be prompted through its API. Visible is not
  addressable; that check is a core change, not something a plugin can
  reach. A [17-line experiment](https://github.com/yanuararistya/herdr/commit/301da71)
  on a fork relaxes it for reported agents.
- **Status is coarse.** working while the far end's screen shows a turn
  in flight, idle otherwise. A real hook on the remote would be better,
  but the point of this is to need nothing there.
- **It polls.** A plugin cannot hook herdr's detection loop. The
  in-tree version of this would not need to.

## Provenance

Written while building [herdr-beb](https://github.com/getbeb/herdr-beb),
which needs the same discovery for a different reason — delivering
cross-machine agent mail into panes. This plugin has no dependency on
that, or on [beb](https://github.com/getbeb/beb).

## License

MIT
