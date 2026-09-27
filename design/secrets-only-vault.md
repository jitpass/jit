# Spec: only secrets go into the vault

Status: approved 2026-09-27 (mockup: JitPass artifact "Secrets-Only Vault"),
in progress
Scope: how `jit migrate` splits a `.env`, where plain settings live, every
reader of a profile entry, moving a single value into or out of the vault,
and a cleanup for profiles protected before this change.
Non-goals: splitting any category other than `.env` files (an MCP env block,
a shell config and the credential stores already hold credentials only), and
changing how backups or Undo work.

## Problem

Protecting a `.env` moves every line into the vault. `ApplyEnvFile` does
this on purpose: the file becomes a live mount that must rebuild the whole
file, and a profile can only map a name to a vault path, so ordinary
configuration had nowhere else to go. On a real machine, one `.env` became a
vault group of 14 entries holding one client secret. The rest were a URL, a
client ID, file names and flags.

That costs three things. The vault's counts stop meaning "secrets", so the
Vault window reads 41 where the user has perhaps 15. Every setting costs a
Touch ID to read. And every later rule that asks "is this vault entry a
secret?" has to work it out again: deep scan's needle gates (D13 in
scan-and-protect.md) and the agent-cache sweep's `EnvOrdinaryValues` (issue
#79) both exist to undo this.

## The rule

**A value goes into the vault when `jit scan` would count it as a secret.**
`audit.ClassifyEnvVar(key, value)` applies the file scanner's rules to one
line: a known token format, a random-looking value, or a secret-shaped name
whose gates pass. It returns one of three classes:

| Class | Meaning | Default |
|---|---|---|
| `secret` | The scan counts the value as a credential. | vault |
| `check` | The name looks like a secret and the value does not (`DB_PASSWORD=hunter2`, `OUTPUT_FILE_DEV_SECRETS=dev_secrets.json`). | vault |
| `setting` | Nothing flags it. | plain |

It judges each line on its own. The file scanner claims only the first
random-looking value in a file, because one is enough to raise its finding.
A split built on those claims would leave the second one in plain text.

The asymmetry behind `check` defaulting to the vault: a setting kept in the
vault costs a Touch ID, and a secret kept in plain text is a leak.

The user can override any line in either direction: `--secret NAME` and
`--setting NAME` on `jit migrate`, and the Vault/Setting control on each line
of the app's Protect sheet, which passes those flags.

## Where settings live

Not in the manifest. `profile.ProfilesDir` documents a manifest as safe to
commit to git because it holds only vault paths. A `.env` is usually
git-ignored and its project's `.jit/profiles/` often is not, so a setting
written into a manifest could end up in a commit.

Settings live beside the vault, in the vault's own layout:

```
~/Library/Application Support/jitpass/settings/<profile>/<NAME>   (0600, dirs 0700)
```

and the manifest entry points at the file:

```yaml
BILLING_URL: jit://setting/billing-sync/BILLING_URL
BILLING_CLIENT_SECRET: billing-sync/BILLING_CLIENT_SECRET
```

A plain file, not an encrypted one: a setting is exactly as readable as the
`.env` line it came from, and reading it needs no Touch ID. That is the
point of the change.

## Readers

Every reader of a profile's values learns the second kind of entry. There
are four kinds of reader:

- **Resolvers** (`inject.Resolve` and the service's grant and job
  resolution) return the setting's value where they would have decrypted a
  vault path.
- **Vault bookkeeping** (orphan and missing-path checks in doctor, reference
  counts, `migrate remove`, `profile drop`) skips settings. It never treats a
  `jit://setting/` pointer as a vault path.
- **The live mount** serves settings to every reader, with or without a
  grant. A decoy exists to stand in for a secret, and a setting was never
  secret. A program without a grant now reads a file whose settings are real
  and whose secrets are decoys, which is closer to what it expects than
  today's all-decoy file.
- **Writers** keep both kinds of entry as they found them.

## Moving one value

- **Move Out of Vault** takes vault entries to settings. It decrypts, so it
  is its own Touch ID every time. It never rides the service session. The
  prompt names what it moves: "Move BILLING_CLIENT_SECRET out of the vault
  (billing-sync)", or a count for several at once. A value the scan counts as
  a secret is allowed out after a warning on its row. The app makes Cancel
  the default button for it, and the user's Findings will show it again.
- **Move to Vault** takes settings to the vault. It is a vault change, so it
  follows the same rule.

## Profiles protected before this change

`jit migrate settings` finds vault entries that `ClassifyEnvVar` calls
settings, in profiles created from a `.env`, and moves them out with one
Touch ID for the whole run. Entries of class `check` stay where they are. The
app announces the count in the Vault window's banner after a deep scan, which
already reads the vault. It is not an exposure, so it never appears in
Findings.

## Decisions (2026-09-27)

- **D1:** plain settings stay out of the vault, as plain text beside it.
  Rejected: keeping them in the vault with a "setting" mark. That is a
  smaller change, but the vault would still hold them.
- **D2:** `check` goes to the vault by default and is flagged "Check this".
- **D3:** the Protect sheet shows setting values before Touch ID (they are
  plain text on disk already) and shows secrets as dots.
- **D4:** the cleanup is announced in the Vault window only.
- **D5:** the cleanup command is `jit migrate settings`.
- **D6:** moving a counted secret out is allowed, with the row warning and
  Cancel as the default button.
- **D7:** settings live outside the manifest (above).
