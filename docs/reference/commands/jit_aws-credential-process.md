## jit aws-credential-process

Print AWS credential_process JSON for a migrated profile

### Synopsis

Not typically run by hand: jit migrate rewrites the matching ~/.aws/config
profile to invoke this command directly
(`credential_process = jit aws-credential-process --profile aws-<name>`),
so the AWS CLI/SDK gets credentials with no file on disk at all.

Requires local auth to resolve the vault the same way jit run/export do:
either a reachable jit agent with an already-unlocked session, or an
interactive context able to show a Touch ID/passcode prompt. Invoked from
a fully headless context (a cron job, a CI runner) with neither will hang
or fail, the same tradeoff jit run/export already accept.

```
jit aws-credential-process --profile <name> [flags]
```

### Options

```
      --profile string   vault profile to resolve (required, e.g. aws-default)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

