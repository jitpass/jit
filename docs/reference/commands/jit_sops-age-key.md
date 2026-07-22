## jit sops-age-key

Print the SOPS age private key from a migrated profile

### Synopsis

Not typically run by hand: sops (v3.10+) runs it via SOPS_AGE_KEY_CMD, its
native hook for fetching the age key from an external command, so decryption
works with no plaintext keys.txt on disk at all:

  export SOPS_AGE_KEY_CMD="jit sops-age-key"

Tools whose embedded sops predates SOPS_AGE_KEY_CMD keep working through the
migrated keys.txt live mount instead (`jit run --with sops` grants the mount
real reads for that run), so this hook is the fast path, not the only path.

Requires local auth to resolve the vault the same way jit run/export do:
either a reachable jit background service with an already-unlocked session, or an
interactive context able to show a Touch ID/passcode prompt. Invoked from
a fully headless context (a cron job, a CI runner) with neither will hang
or fail, the same tradeoff jit run/export already accept.

```
jit sops-age-key [flags]
```

### Options

```
      --profile string   vault profile to resolve (defaults to the one jit migrate creates) (default "sops-age")
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

