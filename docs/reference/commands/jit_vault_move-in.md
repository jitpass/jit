## jit vault move-in

Move plain settings into the vault

### Synopsis

Move each named plain setting into the vault, and point every profile that names it at the
vault entry. The value does not change and files that read it keep working; reading it
then needs Touch ID or a grant, like any secret.

```
jit vault move-in <path>... [flags]
```

### Examples

```
  jit vault move-in billing-sync/BILLING_URL
```

### Options

```
      --format string   output format: "text" (default) or "json"; json needs --yes (default "text")
  -y, --yes             skip the confirmation question; Touch ID is still asked
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

