## jit audit

Show the audit log: what jit commands ran, when, by whom, and every unlock

### Synopsis

jit audit prints the application audit trail, most recent first: one line for
every jit command that ran (what, when, which user and parent process, and
whether it succeeded), interleaved with every local-auth event the service saw
(each unlock and each DECLINED prompt, with how you were asked, what triggered
it, and the secret names each one touched).

Together they answer "what happened on this machine, and who did it": the
command lines are the actions, the auth lines are the approvals those actions
needed. Command arguments are recorded with any secret-looking value masked, so
the log records that a command ran, never the secret it may have carried.

It also records what the service refused at its socket: a rejected peer (a
process the kernel says isn't yours, probing the agent), a malformed request, or
the accept loop failing, each as a kind=error line with the peer's provenance.

Output is logfmt: one key=value line per event, newest first, so it reads and
greps like a real service log. Narrow it without grep using the flags: --kind
cmd,unlock,use,lock,service,error, --status ok|failed|denied, --since and --until
(an age like 2h/3d or a date), --parent (the launching ancestor, e.g. claude),
--secret (a secret name an unlock touched), --user, and --grep (a regexp over the
line). --limit caps how many of the newest MATCHING entries print. Add --follow
(-f) to print the matching tail and then stream new entries live, like tail -f.
For a machine-parseable dump of the same, filtered, data use --format json.

On the auth method: jit challenges with a single macOS prompt that accepts
either a fingerprint or the device passcode, and the OS does not report which
one you used. So the method reads touchid-or-passcode (biometry is available on
this Mac) or passcode (it isn't), never a claim macOS can't back.

Survives restarts and logouts: both halves are durable files alongside the
vault (audit.jsonl and agent-history.jsonl), so this answers for last week as
readily as for the last hour. To scan for plaintext secrets on disk instead,
that command is now `jit scan`. For the service's raw operational output
(startup, mount notes, panics) rather than the event trail, see `jit service log`.

```
jit audit [flags]
```

### Options

```
  -f, --follow          print the matching tail, then stream new entries live (text only)
      --format string   output format: "text" (default) or "json" (default "text")
      --grep string     only entries whose rendered line matches this regular expression
      --kind strings    only these kinds (comma-separated): cmd, unlock, use, lock, service, error
      --limit int       show at most this many recent matching entries (0 for all) (default 50)
      --parent string   only entries whose launched-by ancestor contains this (e.g. claude)
      --secret string   only auth events that touched a secret whose name contains this
      --since string    only entries at or after this time: an age (2h, 90m, 3d) or a date ("2026-07-23" or "2026-07-23 09:00")
      --status string   only this status: ok, failed, or denied
      --until string    only entries at or before this time (same forms as --since)
      --user string     only commands this user ran (auth events carry no user)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

