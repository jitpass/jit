## jit vault get

Decrypt and print a secret

### Synopsis

Prints the decrypted value to stdout, where it lands in your terminal
scrollback and any output capture (tmux, script, CI logs). Prefer
--copy to send it straight to the clipboard instead.

On a terminal, one faint metadata line follows on stderr: when the
secret was last updated, which profiles reference it, and the config
file its migration recorded as the source. Piped or redirected output
receives the value only, never the footer.

```
jit vault get <path> [flags]
```

### Options

```
  -c, --copy   copy the value to the clipboard instead of printing it
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

