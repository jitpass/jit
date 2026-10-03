---
title: Wrap gcloud with jit
description: jit wrap gcloud seals the Google Cloud CLI's own login store in the vault and unseals it for each gcloud, bq, gsutil or credential-helper run, so no refresh token sits in ~/.config/gcloud.
---

# gcloud - Google Cloud CLI login (store)

`gcloud auth login` saves a refresh token in `~/.config/gcloud`: in
`credentials.db` (SQLite) and again in `legacy_credentials/<account>/`.
It does not expire on its own. Google ends it when you revoke it, after
six months unused, or at your organisation's session length. gcloud has
no option to keep it in the keychain, and any program running as you can
copy the files.

`jit wrap gcloud` moves that login store into the vault:

```sh
jit wrap gcloud      # seals the store; shims gcloud, bq, gsutil and the helpers
gcloud auth list     # as before
```

Each run, the shim unpacks the store into a private folder in jit's own
directory, runs gcloud with `CLOUDSDK_CONFIG` pointing there, and removes
the folder when gcloud exits. Your settings (`configurations/`,
`active_config`, logs) stay in `~/.config/gcloud`, and changes to them
are kept. Unsealing the store is one Touch ID naming your `gcp`
credential, like any other secret.

The access-token cache (`access_tokens.db`) is never stored: each run
starts without it and gcloud fetches a fresh access token.

## Logging in and out

Log in as usual. `gcloud auth login` runs inside the private folder, and
the new login goes straight into the vault. Nothing is written to
`~/.config/gcloud`. A logout or `gcloud auth revoke` is sealed the same
way. Saving a new login can take a Touch ID if the vault has locked
meanwhile. If you decline, jit leaves the login in `~/.config/gcloud` in
plaintext rather than lose it, and says so.

## What else the wrap covers

| Program | How |
|---|---|
| `bq`, `gsutil` | their own shims |
| `docker pull` from Artifact Registry or GCR | the `docker-credential-gcloud` shim |
| `git` over Cloud Source Repositories | the `git-credential-gcloud` shim |
| `kubectl` on GKE | the GKE auth plugin runs `gcloud`, which the shim covers |
| Terraform, client libraries | they use application-default credentials, not this store: [migrate that file](../migrate/gcp.md) |

`gcloud auth application-default …` commands keep running inside
`jit run --with gcp` when the ADC file is migrated, as the earlier gcloud
wrap did.

## Limits

- While a command runs, its private folder holds the login in plaintext.
  The folder is owner-only and removed when the command exits; a run that
  is killed has its folder removed by the next run.
- A program that runs gcloud by its full path, or reads
  `~/.config/gcloud` itself, sees no login. That fails loudly; it never
  leaks.
- If something logs in without the shim, the plaintext store is back.
  The next wrapped run uses it and tells you to run `jit wrap gcloud`
  again.
- Only the default config folder is sealed. With `CLOUDSDK_CONFIG` set to
  another folder, gcloud runs without jit and says so.

## Verify

```sh
gcloud auth list
ls ~/.config/gcloud      # no credentials.db, no legacy_credentials
```

## Undo

`jit wrap undo gcloud` writes the login back to `~/.config/gcloud` (after
a fresh Touch ID) and removes all five shims. The vault copy is kept;
`jit vault rm gcloud-cli/store` deletes it. `jit uninstall --restore` puts
back the most recent login too.
