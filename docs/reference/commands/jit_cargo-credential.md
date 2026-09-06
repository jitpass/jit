## jit cargo-credential

Implement cargo's credential-provider protocol for a migrated registry token

### Synopsis

Not typically run by hand: jit migrate writes a cargo-credential-jit
wrapper that invokes this command and registers it (last, so it takes
precedence) in ~/.cargo/config.toml's global-credential-providers, so
cargo fetches its registry token from the vault with no plaintext file
on disk.

The protocol's three kinds map to the vault: `get` serves the token from
the registry's cargo-<name> profile (answering not-found for a registry
jit holds nothing for, so cargo falls back to credentials.toml exactly
as if jit weren't installed); `login` (what `cargo login` calls) saves
the new token to the vault, so a re-login lands in the vault instead of
back in a plaintext file; `logout` removes it.

Requires local auth to resolve the vault the same way jit run/export do:
either a reachable jit background service with an already-unlocked session, or an
interactive context able to show a Touch ID/passcode prompt.

```
jit cargo-credential [--cargo-plugin]
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

