## jit git-credential

Implement git's credential-helper protocol for migrated HTTPS logins

### Synopsis

Not typically run by hand: jit migrate writes a git-credential-jit
helper script (on PATH via ~/.jit/shims) and sets credential.helper to it
in your git config, so `git push` over HTTPS (and submodule fetches, LFS,
and anything else that shells out to git) fetches the credential from the
vault instead of ~/.git-credentials.

The three verbs are git's own protocol, each reading a set of key=value
attributes from stdin (protocol, host, path, username, password),
terminated by a blank line: `get` reads the host and prints the matching
`username=`/`password=` pair, or nothing when jit holds no credential for
that host, so git falls through to its next helper or prompts; `store`
reads a credential and saves it to the vault, so a push that authenticated
with a typed-in password lands in the vault instead of back in plaintext;
`erase` removes it. jit keys on host alone, matching git's default
(credential.useHttpPath=false).

`get` for a host jit holds nothing for, and `erase`, never cost a Touch ID
prompt. A successful `get` resolves the vault the same way jit run/export
do: either a reachable jit background service with an already-unlocked session, or an
interactive context able to show a Touch ID/passcode prompt.

```
jit git-credential <get|store|erase>
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

