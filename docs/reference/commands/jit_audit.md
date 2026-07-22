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

Output is logfmt: one key=value line per event, newest first, so it reads and
greps like a real service log (filter with grep 'kind=unlock', 'status=denied',
and the like). For a machine-parseable dump of the same data use --format json.

On the auth method: jit challenges with a single macOS prompt that accepts
either a fingerprint or the device passcode, and the OS does not report which
one you used. So the method reads touchid-or-passcode (biometry is available on
this Mac) or passcode (it isn't), never a claim macOS can't back.

Survives restarts and logouts: both halves are durable files alongside the
vault (audit.jsonl and agent-history.jsonl), so this answers for last week as
readily as for the last hour. To scan for plaintext secrets on disk instead,
that command is now `jit scan`.

```
jit audit [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
      --limit int       show at most this many recent entries (0 for all) (default 50)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

