---
title: Wrap the Azure CLI with jit
description: jit wrap az seals the Azure CLI's login (refresh tokens and service principal secrets) in the vault and unseals it for each az run, so nothing sits in ~/.azure in plaintext.
---

# az - Azure CLI login (store)

The Azure CLI keeps its login in `~/.azure` in plaintext on macOS:

- `msal_token_cache.json`: a refresh token for each account you signed in
  with. It lasts 90 days and is renewed every time it is used.
- `service_principal_entries.json`: the client secret of each service
  principal you logged in as, valid until it is rotated.

Any program running as you can copy them. The CLI's own option to use the
keychain is experimental and off on macOS, and it breaks service principal
logins.

`jit wrap az` moves both files into the vault:

```sh
jit wrap az                                          # seals the login; shims az
az account get-access-token --query expiresOn -o tsv # as before
```

Each run, the shim unpacks the login into a private folder in jit's own
directory, runs az with `AZURE_CONFIG_DIR` pointing there, and removes the
folder when az exits. Your settings (`config`, `azureProfile.json`,
clouds, logs) stay in `~/.azure`, and changes to them are kept. Unsealing
the login is one Touch ID naming your `azure` credential.

## Refreshes, logins and logouts

az renews its refresh token on every refresh, about once an hour while you
use it. Each run seals the new token back into the vault, silently. Runs
can overlap (an `az aks create` in one terminal, an `az login` in another):
each run's changes are merged into the vault's copy, so neither loses the
other's login.

`az login`, `az logout` and `az account clear` work as usual, and their
result goes straight into the vault. If saving it needs a Touch ID and you
decline, jit leaves the login in `~/.azure` in plaintext rather than lose
it, and says so.

## What else the wrap covers

Everything that borrows the az login runs `az account get-access-token`
from your PATH, so the one shim covers it:

| Program | How it gets the login |
|---|---|
| Azure SDKs (`AzureCliCredential`, `DefaultAzureCredential`) | they run `az` |
| Terraform's `azurerm` provider (Azure CLI auth) | it runs `az` |
| `kubectl` on AKS with `kubelogin -l azurecli` | kubelogin runs `az` |

## Limits

- While a command runs, its private folder holds the login in plaintext.
  The folder is owner-only and removed when the command exits; a run that
  is killed has its folder removed by the next run.
- A program that runs az by its full path, or reads `~/.azure` itself,
  sees no login. That fails loudly; it never leaks.
- If something logs in without the shim, the plaintext login is back. The
  next wrapped run uses it and tells you to run `jit wrap az` again.
- Only the default folder is sealed. With `AZURE_CONFIG_DIR` set to another
  folder, az runs without jit and says so.
- `az logout` only deletes the local copy. If a refresh token was exposed,
  revoke your sign-in sessions in Entra ID; for a service principal,
  rotate its secret.
- `jit doctor` reports a folder a killed run left behind, and a plaintext
  login that came back while az is wrapped.

## Verify

```sh
az account get-access-token --query expiresOn -o tsv
ls ~/.azure      # no msal_token_cache.json, no service_principal_entries.json
```

## Undo

`jit wrap undo az` writes the current login back to `~/.azure` (after a
fresh Touch ID) and removes the shim. The vault copy is kept;
`jit vault rm azure-cli/store` deletes it. `jit uninstall --restore` puts
back the current login too.
