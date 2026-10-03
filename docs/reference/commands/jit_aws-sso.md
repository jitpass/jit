## jit aws-sso

Print AWS credential_process JSON for a sealed AWS profile

### Synopsis

Not typically run by hand: jit migrate rewrites each AWS SSO and `aws login`
profile in ~/.aws/config to `credential_process = jit aws-sso --profile <name>`.
The login lives in the vault; this unpacks it into a private folder for one
run of `aws configure export-credentials` (AWS's own CLI does the refresh),
seals it again if the run refreshed it, and prints the credentials. A login
`aws sso login` just wrote to ~/.aws/sso/cache is moved into the vault first.
Needs the AWS CLI v2 on PATH.

```
jit aws-sso --profile <name> [flags]
```

### Options

```
      --profile string   the AWS profile to fetch credentials for (supplied by ~/.aws/config)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit aws-sso login](jit_aws-sso_login.md)	 - Sign a sealed AWS profile in again, straight into the vault
* [jit aws-sso logout](jit_aws-sso_logout.md)	 - Sign out of every sealed AWS SSO and `aws login` session

