# Spike Findings: the Azure CLI's login store, sealed

**Question:** the Azure CLI keeps its logins in `~/.azure` in plaintext on
macOS: `msal_token_cache.json` (a refresh token per account, Entra ID's
90-day sliding window) and `service_principal_entries.json` (service
principal client secrets). #214 reports both. Can jit take them off disk:
(a) by switching az to the keychain, as it did for kubelogin, or (b) by
sealing them like gcloud's store (`design/gcloud-sealed-store.md`)?

**Environment:** azure-cli 2.90.0 (Homebrew; MSAL 1.36.0,
msal-extensions 1.3.1). `fake_entra.py` answers what az needs from Entra
ID (v2.0 discovery, device code, token: device-code, refresh and
client-credentials grants, rotating the refresh token on every call) and
the two ARM calls `az login` makes (tenants, subscriptions). MSAL refuses a
non-https authority, so it serves TLS with a throwaway certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
PORT=8443 python3 fake_entra.py &
export AZURE_CONFIG_DIR=<scratch> REQUESTS_CA_BUNDLE=$PWD/cert.pem AZURE_CORE_COLLECT_TELEMETRY=false
az config set core.instance_discovery=false
az cloud register -n FakeCloud --endpoint-resource-manager https://127.0.0.1:8443/arm/
az cloud set -n FakeCloud
az login --use-device-code
```

(`core.instance_discovery=false` stops MSAL asking login.microsoftonline.com
about the fake authority; the fake serves `/metadata/endpoints` so `az cloud
register` can build the cloud from it.)

## E1: a real `az login` works against the fake

Device-code login, then a refresh per tenant, then ARM's tenants and
subscriptions. `msal_token_cache.json` holds 3 access tokens, 2 ID tokens,
1 account and **1 refresh token**, in plaintext JSON.

## E2: what a fetch writes

- `az account get-access-token` with a valid access token makes **no**
  request and writes **no** file.
- With the access tokens expired, it makes one refresh-grant call. The
  refresh token **rotates** (`rt-8` → `rt-10`) and only
  `msal_token_cache.json` changes.

## E3: relocation works, and only the secrets need to be real files

A run dir holding a copy of `msal_token_cache.json`, every other entry of
`~/.azure` symlinked, `AZURE_CONFIG_DIR` pointing at it:

- a cached fetch, a refresh, `az account set` and a fresh `az login` all
  work;
- every write except the token cache's went **through** the symlinks
  (`azureProfile.json` and `config` changed in `~/.azure`), so no settings
  need adopting back, unlike gcloud's;
- the refresh rotated the token in the run dir only.

## E4/E6: service principals

`az login --service-principal -p <secret>` stores the client secret in
`service_principal_entries.json` in plaintext. The command log in
`~/.azure/commands/` **redacts** it, and no access token appears in those
logs (debug off).

In a run dir the SP store behaves like the token cache: a second SP login,
`az logout --username` and `az account clear` changed only the run dir's
copies, and `az account clear` deleted both files there (a sign-out the
reseal would see as an empty store).

Only these two files hold token material. A grep for every token and
secret the fake issued found nothing else in `~/.azure`.

## E5: az's own keychain mode is not a fix

`az config set core.encrypt_token_cache=true` makes az keep both stores in
the macOS keychain (`persistence.py`: `KeychainPersistence(location,
"my_service_name", "my_account_name")`). It is off by default on macOS and
marked EXPERIMENTAL, and the names are hard-coded: **the token cache and
the service-principal store share one keychain item.** A user login
followed by an SP login crashes:

```
TypeError: string indices must be integers, not 'str'
```

(the SP store read the user's token cache). A switch that breaks the
service-principal login is not one jit can make for the user. The item's
ACL also trusts the Python that created it, so any script run by that
interpreter reads it without a prompt.

## Not verified

- **Whether Entra ID still honours a refresh token that has been rotated
  away.** The fake accepts any token. The design must not depend on the
  answer: concurrent runs must not lose a rotated token or a new login
  (see Implication).
- A login against Entra ID itself. The login runs az's code unchanged,
  under a different `AZURE_CONFIG_DIR`.

## Implication

Option (b), gcloud's model. `jit wrap az` seals
`msal_token_cache.json` and `service_principal_entries.json` as one vault
value (class `azure`). The `az` shim unseals them into a run dir with
everything else symlinked, runs az with `AZURE_CONFIG_DIR` on it, and
reseals on change.

What consumes the login is `az` itself, found on PATH, and so is every
tool that borrows it: azure-identity's and azidentity's
`AzureCliCredential`, Terraform's azurerm and kubelogin `-l azurecli` all
run `az account get-access-token`. They reach the shim.

**One difference from gcloud: reseal by merge, not overwrite.** The
refresh token rotates on every refresh, and az commands run long and in
parallel (`az aks create` takes minutes). The reseal should therefore
3-way merge each store's entries (the run's changes since its baseline,
laid over the vault's current copy, under a short lock), so a long run's
refresh cannot drop a login another run made. Both files are JSON
collections keyed by entry (MSAL's own `PersistedTokenCache` reloads and
merges the same way).
