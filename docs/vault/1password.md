# Use secrets that live in 1Password

`jit vault link` stores a 1Password secret reference instead of a value.
The secret itself never leaves 1Password: the vault holds the `op://`
reference (encrypted, like any secret), and every delivery surface
(`jit run`, credential helpers, mounts, `jit export`) resolves it through
the 1Password CLI at the moment of use.

Use this when 1Password is already your system of record. You keep
rotating and sharing the value there; jit stays the layer that decides
which process receives it, serves decoys to everything else, and writes
the audit trail. A copy that could drift is never created.

## Requirements

- The 1Password desktop app, signed in.
- The 1Password CLI: `brew install 1password-cli`.
- The app integration: in 1Password, Settings > Developer >
  **Integrate with 1Password CLI** (turn on Touch ID in the app's
  Security settings if you want fingerprint unlock).

jit is never given an account credential, token, or config. It talks to
the `op` binary you installed, and refuses to run one that does not carry
1Password's own Developer ID code signature.

## Linking happens by itself during migrate

With `op` installed and signed in, every `jit migrate` run checks the
values it is about to vault against your 1Password (one authenticated
check per run, after you confirm the plan): a value that byte-exactly
matches a concealed 1Password field is stored as a reference, not a
copy, and the mutation log lists each one under a `[1Password]`
heading. A `.env` you kept for `op run`, full of `op://` values,
converts the same way: each reference stays a reference, so it keeps
resolving after migration. Matching is exact, values shorter than 8
characters never match, and `--no-1password` restores plain copies.
If the check fails (signed out, app locked), the run continues with
copies and says so; nothing breaks because 1Password is unavailable.

## Link a secret by hand

Copy the reference in the 1Password app: open the item, click the field's
menu, **Copy Secret Reference**. Then:

```sh
jit vault link stripe/live "op://Private/Stripe/credential"
```

jit test-resolves the reference first, so a typo, a signed-out CLI, or a
deleted item fails here rather than at first use (`--no-verify` skips the
test for offline setup). Then it stores the reference under a fresh
Touch ID.

First use in a terminal session can show two prompts, and they are
different decisions: jit's Touch ID approves *this process getting the
secret*; 1Password's dialog approves *this terminal using its CLI*. Both
remember, so later uses are quiet.

Item and vault IDs work in place of names (`op item get <item> --format
json` shows them) and survive renames in 1Password; names are easier to
read. Query parameters pass through, so a reference like
`"op://vault/item/one-time password?attribute=otp"` yields a fresh
one-time code on every resolve.

## Use it

The linked path works everywhere a vault path works. In a profile:

```yaml
# .jit/profiles/deploy.yaml
STRIPE_KEY: stripe/live
```

```sh
jit run --profile deploy -- ./deploy.sh
```

`jit vault get stripe/live` prints the resolved value;
`--format json` adds the reference it resolved through. `jit vault list
-l` shows linked entries under the `1password` class.

## Rotation, backup, removal

- **Rotate in 1Password.** The next resolve returns the new value; there
  is nothing to re-link.
- **`jit vault export` backs up the reference, never the value**: an
  export is a vault backup, not a 1Password read. Imported on another
  Mac, the link resolves there as soon as `op` is signed in.
- **`jit vault rm`** removes the link like any secret. The 1Password item
  is untouched; jit never writes to 1Password.

## When it fails

Failures are loud and local: a deleted item, a signed-out CLI, or a
locked 1Password fails the resolve with op's own error in front of you
and in `jit audit`. Nothing falls back to a cached value, because there
is no cached value.

## Check link health

`jit vault list` counts linked secrets in its footer and, with `-l`,
tags each linked entry; `jit doctor` automatically checks (prompt-free)
that the op CLI is installed and carries 1Password's own code
signature whenever linked secrets exist. `jit doctor --1password` goes
further and test-resolves every link, so a reference broken by a
deleted or renamed item surfaces as a finding now rather than the
moment a tool needed the value. That sweep takes one Touch ID (the
stored references are encrypted like any secret) and 1Password may
show its own prompt, which is why it never runs by default.

## Limits

jit never writes to 1Password, and the background service resolves at
unlock/refresh time, so linked secrets in mounts want you present (the
same moments Touch ID already wants you). Migrate links what it
touches; there is no bulk import of a whole 1Password vault yet, and
`jit scan` never contacts 1Password at all (it only notes `op://`
references it sees in flagged files).
