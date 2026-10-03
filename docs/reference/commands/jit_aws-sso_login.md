## jit aws-sso login

Sign a sealed AWS profile in again, straight into the vault

### Synopsis

Runs AWS's own sign-in for a profile jit sealed, against the sealed
login rather than ~/.aws: `aws login` for a console-credentials profile,
`aws sso login` for an SSO one. The browser flow is AWS's; the new login
goes into the vault without touching disk in plaintext.

An `aws login` profile needs this: `aws login` refuses a profile that
fetches through jit. An SSO profile can also use plain `aws sso login`,
which jit seals on the next use.

```
jit aws-sso login --profile <name> [flags]
```

### Options

```
      --profile string   the sealed AWS profile to sign in
      --remote           sign in with a browser on another device (over SSH)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit aws-sso](jit_aws-sso.md)	 - Print AWS credential_process JSON for a sealed AWS profile

