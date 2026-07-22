## jit k8s-exec-credential

Print a Kubernetes ExecCredential JSON for a migrated profile

### Synopsis

Not typically run by hand: jit migrate rewrites the matching kubeconfig
user's `exec` block to invoke this command directly, so kubectl/client-go
get credentials with no plaintext token or key on disk at all.

Requires local auth to resolve the vault the same way jit run/export do:
either a reachable jit background service with an already-unlocked session, or an
interactive context able to show a Touch ID/passcode prompt. Invoked from
a fully headless context (a cron job, a CI runner) with neither will hang
or fail, the same tradeoff jit run/export already accept.

```
jit k8s-exec-credential --profile <name> [flags]
```

### Options

```
      --profile string   vault profile to resolve (required, e.g. k8s-myuser)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

