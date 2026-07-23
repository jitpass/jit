## jit docker-credential

Implement Docker's credential-helper protocol for migrated registry logins

### Synopsis

Not typically run by hand: jit migrate writes a docker-credential-jit
helper script (on PATH via ~/.jit/shims) and routes registries to it in
~/.docker/config.json (credHelpers per migrated registry, plus credsStore
when the config had no store at all), so docker fetches registry
credentials from the vault with nothing on disk but docker's own empty
"auths" markers.

The four verbs are Docker's own protocol, each reading its payload from
stdin: `get` reads a registry address and prints the credential as JSON,
or the protocol's exact "credentials not found in native keychain"
sentinel when jit holds nothing for that registry, so docker falls
through to anonymous access; `store` (what `docker login` calls) reads
a JSON credential and saves it to the vault, so a re-login lands in the
vault instead of back in base64; `erase` (`docker logout`) removes it;
`list` prints an empty JSON object, deliberately: a truthful listing
would need a vault unlock inside headless docker calls, and docker still
resolves every registry's real credential per-registry via `get`.

`get` for a registry jit holds nothing for, and `erase`, never cost a
Touch ID prompt. A successful `get` resolves the vault the same way
jit run/export do: either a reachable jit background service with an already-unlocked
session, or an interactive context able to show a Touch ID/passcode
prompt.

```
jit docker-credential <get|store|erase|list>
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

