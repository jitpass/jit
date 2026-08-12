## jit vault get

Decrypt and print a secret

### Synopsis

Prints the decrypted value to stdout, where it lands in your terminal
scrollback and any output capture (tmux, script, CI logs). Prefer
--copy to send it straight to the clipboard instead.

On a terminal, one metadata line follows on stderr: when the
secret was last updated, which profiles reference it, and the config
file its migration recorded as the source. Piped or redirected output
receives the value only, never the footer.

--json prints an object with the value and the envelope's provenance
(class, group, origin) and timestamps instead of the bare value.

Requires a fresh Touch ID/passcode on every run, never the cached service
session, so a decrypted secret can never be read silently, even on an
already-unlocked machine.

```
jit vault get <path> [flags]
```

### Examples

```
  jit vault get stripe/dev-key
  jit vault get stripe/dev-key --copy     # to the clipboard, not the screen
  jit vault get stripe/dev-key --format json
```

### Options

```
  -c, --copy            copy the value to the clipboard instead of printing it
      --format string   output format: "text" (default, the bare value) or "json" (the value plus provenance and timestamps) (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

