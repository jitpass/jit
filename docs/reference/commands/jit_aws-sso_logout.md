## jit aws-sso logout

Sign out of every sealed AWS SSO and `aws login` session

### Synopsis

Runs `aws sso logout` on the sealed login, the way it would run on
~/.aws/sso/cache: Identity Center ends the session server-side and the
token is deleted. Sealed `aws login` sessions are deleted the way
`aws logout --all` deletes them. Plain `aws sso logout` and `aws logout`
cannot do this once the login is sealed, since the cache they read is
empty.

```
jit aws-sso logout
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit aws-sso](jit_aws-sso.md)	 - Print AWS credential_process JSON for a sealed AWS profile

