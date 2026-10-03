## jit aws-sso

Print AWS credential_process JSON for a sealed AWS profile

### Synopsis

Not run by hand: jit migrate points each AWS SSO and `aws login` profile
in ~/.aws/config at `jit aws-sso --profile <name>`. The login lives in the
vault; this unpacks it for one run of AWS's own `aws configure
export-credentials`, which refreshes it, seals it again, and prints the
credentials. A login `aws sso login` just wrote is moved into the vault
first. Needs the AWS CLI v2 on PATH.

Two subcommands are yours to run: `jit aws-sso login --profile <name>`
signs a profile in again, and `jit aws-sso logout` signs out.

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

