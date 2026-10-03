# Spec: the Azure CLI's login, sealed in the vault

Status: built 2026-10-02 (spike `spike/azure-cli-store`, #218)
Scope: `~/.azure/msal_token_cache.json` (Entra ID refresh tokens) and
`~/.azure/service_principal_entries.json` (service principal secrets).
Non-goals: a non-default `AZURE_CONFIG_DIR` (left alone, as gcloud's
`CLOUDSDK_CONFIG`); az's own keychain mode (spike E5: off on macOS,
experimental, and broken for service principals); Azure PowerShell, azd and
VS Code, which keep their own caches.

Companion: `design/gcloud-sealed-store.md`, whose model this reuses. Read it
first; this records only what differs.

## Problem

The Azure CLI keeps its logins in plaintext on macOS. The MSAL token cache
holds a refresh token per account, valid 90 days and renewed on every use.
`service_principal_entries.json` holds each service principal's client
secret, valid until rotated. Any process running as the user can copy
either. Every tool that borrows the az login runs `az account
get-access-token` from PATH: azure-identity's and azidentity's
`AzureCliCredential`, Terraform's azurerm and `kubelogin -l azurecli`.

## The mechanism

gcloud's (D1–D10 there): `jit wrap az` seals the two files as one vault
value (`azure-cli/store`, class `azure`, consent-gated). The `az` shim runs
`jit az-run`, which:

1. unpacks the files into a private run dir with every other `~/.azure`
   entry symlinked;
2. runs az with `AZURE_CONFIG_DIR` on the run dir;
3. reseals if the run changed the store.

Settings writes (`azureProfile.json`, `config`, `clouds.config`, command
logs) go through the links, so `~/.azure` keeps them (spike E3).

The machinery is one table, `migrate.ToolStores()` (`ToolStore`: name,
vault path, class, layout, config dir and its variable). Sealing,
unsealing, the run, doctor, the service's sweep and Remove JitPass's
restore read it, so gcloud and az take the same code path.

## Decisions

**A1. Reseal by merge, not overwrite.** The refresh token rotates on every
refresh (spike E2), and az commands run long and side by side (`az aks
create` takes minutes). With gcloud's overwrite, a long run's reseal would
drop a login another run sealed meanwhile.

- `ReadSealed` records the wrapped data key it read under. Every write
  makes a new one, so at reseal time a different key means another run
  sealed in between, and nothing is decrypted to find that out.
- Only then is the current copy read. The run's changes since its base
  (entries added, changed or removed) are laid over it, entry by entry:
  the MSAL cache by section and key, service principals by client and
  tenant (`MergeAzureStore`).
- A file the merge cannot parse is taken whole from the run, which is never
  worse than no merge.
- A short `flock` (`<root>/.az-run.lock`) serialises the reseals
  themselves, never the az commands.

Whether Entra ID still honours a rotated-away refresh token was not
verified. The merge keeps the newest one regardless.

**A2. A routine refresh is silent.** The store changes on every refresh, so
a reseal that kept the same files says nothing. A login or a sign-out (a
file appears or goes) is announced, as gcloud's always are. stderr stays
clean for the tools that parse az.

**A3. No backup per reseal.** Unlike gcloud's, which changes only at a
login, this store would leave a backup every hour. `jit wrap undo az` and
`jit uninstall --restore` write back the vault's current copy (AWS SSO
D10's reasoning).

**A4. Nothing is ephemeral.** az rebuilds no secret cache of its own, and
the command logs redact service principal secrets (spike E4), so the layout
has secrets and settings only.

## Limits

gcloud's:

- the run dir holds the login while a command runs;
- a program that reads `~/.azure` itself sees no login;
- a login made without the shim is back in plaintext, and doctor and the
  next run say so;
- only the default config dir is sealed.
