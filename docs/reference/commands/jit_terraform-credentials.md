## jit terraform-credentials

Implement Terraform's credentials-helper protocol for a migrated token

### Synopsis

Not typically run by hand: jit migrate writes a terraform-credentials-jit
helper script that invokes this command, and a credentials_helper block in
~/.terraformrc, so terraform fetches its API token from the vault with no
file on disk at all.

The three verbs are Terraform's own protocol: `get <host>` prints the
token as JSON (an empty object when jit holds nothing for that host, so
terraform falls through to anonymous access exactly as if no credentials
file entry existed); `store <host>` (what `terraform login` calls) reads
the token JSON from stdin and saves it to the vault, so a re-login lands
in the vault instead of back in a plaintext file; `forget <host>`
(`terraform logout`) removes it.

Requires local auth to resolve the vault the same way jit run/export do:
either a reachable jit agent with an already-unlocked session, or an
interactive context able to show a Touch ID/passcode prompt.

```
jit terraform-credentials <get|store|forget> <hostname>
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

