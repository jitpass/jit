## jit vault link

Store a 1Password reference instead of a value

### Synopsis

Links <path> to a secret that stays in 1Password: the vault stores the
op:// reference (encrypted, like any secret), and every use (jit run,
credential helpers, mounts) resolves it through the 1Password CLI at
that moment. Rotate and share the value in 1Password; jit never keeps
a copy that can drift.

Copy the reference from the 1Password app (field menu > Copy Secret
Reference). Item and vault IDs also work in place of names and survive
renames.

The link is test-resolved through `op` first, so a typo or a signed-out
CLI fails here, not at first use; --no-verify skips that (offline setup).
Requires the 1Password CLI (`brew install 1password-cli`) with the
desktop app integration on.

First use in a terminal session may show two prompts: jit's Touch ID
and 1Password's own authorization dialog. Each gates a different thing
(jit: this process gets the secret; 1Password: this terminal may use
its CLI) and both remember, so later uses are quiet.

Requires a fresh Touch ID/passcode on every run, never the cached service
session, same as `jit vault set`.

Overwriting an existing secret asks first; -y/--yes skips that question,
as it does on every other jit command.

```
jit vault link <path> <op://vault/item/field> [flags]
```

### Examples

```
  jit vault link stripe/live "op://Private/Stripe/credential"
  jit vault link deploy/token "op://dev/GitHub/credentials/token" --no-verify
```

### Options

```
      --no-verify op   skip the trial resolve through op (offline setup)
  -y, --yes            overwrite an existing secret without confirmation
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

