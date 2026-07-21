## jit vault

Manage the local encrypted secret vault

### Synopsis

jit vault stores each secret as its own encrypted file under jit's data
directory, no monolithic database.

Every command that reads, writes, or destroys a secret (get, set, rm,
import, restore, clean, prune, delete, export) requires a fresh Touch
ID/passcode on EACH invocation, whether or not the background agent's
session is unlocked - these commands never ride the cached session, so a
process running as you on an unlocked machine still can't read or destroy
the vault without a live human gesture. Only `list` and `history` are
prompt-free: they show secret names and version timestamps, never a value.

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit vault clean](jit_vault_clean.md)	 - Delete every secret in the vault (the vault itself stays set up)
* [jit vault delete](jit_vault_delete.md)	 - Permanently destroy the whole vault, including its encryption key
* [jit vault export](jit_vault_export.md)	 - Export every secret to a passphrase-encrypted local backup file
* [jit vault get](jit_vault_get.md)	 - Decrypt and print a secret
* [jit vault history](jit_vault_history.md)	 - List a secret's archived previous versions
* [jit vault import](jit_vault_import.md)	 - Restore secrets from a jit vault export file
* [jit vault init](jit_vault_init.md)	 - Set up the local vault (generates the master encryption key)
* [jit vault list](jit_vault_list.md)	 - List stored secret paths (names only, never values)
* [jit vault prune](jit_vault_prune.md)	 - Delete stale encrypted file backups, keeping each file's newest
* [jit vault rekey](jit_vault_rekey.md)	 - Rotate the vault's master encryption key
* [jit vault restore](jit_vault_restore.md)	 - Bring back an archived previous version of a secret
* [jit vault rm](jit_vault_rm.md)	 - Delete a secret
* [jit vault set](jit_vault_set.md)	 - Encrypt and store a secret

