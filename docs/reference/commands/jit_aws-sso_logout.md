## jit aws-sso logout

Sign out of every sealed AWS SSO session

### Synopsis

Runs `aws sso logout` on the sealed login, the way it would run on
~/.aws/sso/cache: Identity Center ends the session server-side and the
token is deleted. Plain `aws sso logout` cannot do this once the login is
sealed, since the cache it reads is empty.

```
jit aws-sso logout
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit aws-sso](jit_aws-sso.md)	 - Print AWS credential_process JSON for a sealed SSO profile

