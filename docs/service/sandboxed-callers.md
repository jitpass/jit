---
title: Calling jit from a sandbox
description: What a sandboxed shell - a coding agent, a CI runner - needs in order to reach the background service, and what jit does when it cannot.
---

# Calling jit from a sandbox

A growing share of the commands jit runs are typed by something that isn't a
person: a coding agent working in your repo, a CI runner, anything launched
under `sandbox-exec`. That is a good fit for jit rather than an awkward one.
A sandboxed process that needs a token is exactly the caller that should be
asking the service for it, because the secret is handed over the socket and
never lands anywhere the sandbox can see.

It needs one thing to be allowed, and the failure without it used to be
badly misreported.

## Allow the socket

On macOS, a sandbox profile that denies outbound network access denies
**unix-domain sockets too** - the same rule covers both. jit talks to its
background service over `~/Library/Application Support/jitpass/agent.sock`,
so a shell sandboxed that way is refused the connect, and nothing that needs
the service works.

The fix is to allow that one path. In Claude Code, that is a key in
`~/.claude/settings.json`:

```json
{
  "sandbox": {
    "network": {
      "allowUnixSockets": [
        "/Users/you/Library/Application Support/jitpass/agent.sock"
      ]
    }
  }
}
```

Other harnesses spell it differently - a seatbelt profile wants
`(allow network-outbound (literal "..."))` - but it is the same grant, and it
is the *only* one jit needs. In particular:

**Do not give the sandbox write access to jit's config directory.** It is
tempting, because one thing (below) does still degrade without it. But that
directory holds `grants.json`, `mounts.yaml`, the vault tree and the backup
index, and handing a sandboxed process write access to all of it to fix a
logging gap trades away most of what the sandbox was for.

## What jit says when the socket is blocked

A refused connect and a stopped service look identical from the outside, and
jit used to report the first as the second - sending you to
`jit service restart` for a service that had never stopped, while
`jit unlock` tried to start a second one.

They are distinguishable at the kernel: a refused connect is `EPERM`, a
service that exited is `ENOENT` or `ECONNREFUSED`. jit now tells them apart
and says so, without offering a restart that would fix nothing:

```
service  ○ running, but this shell was refused its socket
      → a sandbox is the usual cause — allow ~/Library/Application
        Support/jitpass/agent.sock in its config
```

`jit status`, `jit service status`, `jit doctor`, `jit unlock` and the
`jit migrate` trailer all report it this way. Two rows of `jit status` are
worth calling out, because they used to state something false rather than
merely unhelpful: mounts and grants are the service's own facts, so a shell
that cannot reach it now reports them as unknown. Before, a sandboxed shell
was told it had **no grants** - which is wrong exactly when a grant is
active, the case an agent working under one most needs to see.

`jit service status --format json` carries `"socket_blocked": true` alongside
`"running": false`. A script that alerts on the second should check the
first: nothing is down, and no restart it could run would change the answer.

## What works with no service at all

These need no socket and no unlock, so they work inside a sandbox whether or
not you allow anything:

- [`jit scan`](../audit/index.md) - read-only under every flag
- [`jit doctor`](./index.md) - metadata only, no vault decrypt
- `jit status` - reports what it can reach and says what it cannot
- `jit migrate --dry-run` - previews without writing

A sandboxed command that needs a secret and cannot reach the service falls
back to its own Touch ID prompt, so it still works; it just doesn't share
the session, and prompts once per command instead of once per session.

## The audit trail

jit records every invocation to `audit.jsonl` in its config directory. A
sandboxed caller cannot write there, so those records used to be lost
outright - with `recording audit event: operation not permitted` on stderr
and nothing in the trail. The invocations most worth having, an agent
running jit on your behalf, were the ones going missing.

They are now handed to the service over the same socket, which is already
authenticated and already writing to that file, so a sandboxed caller is
fully audited with no write access anywhere. The service re-stamps the three
facts it can actually vouch for - the uid the kernel proved, the pid it saw
connect, and its own clock at receipt - and re-applies the secret masking on
arrival. The rest stays the caller's account of itself, exactly as it was
when the caller wrote the file directly.

When no service is running, jit writes the file itself as before, so a
machine without one loses nothing. The gap that remains is narrow and real:
a caller that can write nothing **and** reach no service has nowhere to put
the record, and it is lost.

## Sandboxes that run in a VM

Some AI apps run their agent inside a Linux virtual machine: Claude Desktop's
Cowork is one. Nothing in that VM can reach a unix socket on your Mac, and it
should not: a grant would hand the VM the secrets. Those apps reach jit
through [AI jobs](./ai-jobs.md) instead. `jit mcp`, which the app starts on
your Mac, runs a command you approved and hands the VM its output with every
secret value hidden.

## Known rough edges

- **The very first jit run on a machine** writes a device-id file, which a
  sandbox that blocks writes refuses - so a brand-new install cannot
  complete its first command from inside one. Run any jit command outside
  the sandbox once first.
- **Live mounts** ([`jit run`](../run/index.md) tiers 3-4) keep serving decoy
  content: real values reach a reader only through a run-scoped grant, and
  asking for that grant means reaching the service. Env injection (tier 1)
  still works, through the local fallback above.
- **The service must be restarted** after upgrading to a jit that has this,
  before a sandboxed caller's audit records start landing: a new CLI against
  an older service falls back to writing the file itself, which is exactly
  the thing the sandbox blocks.
