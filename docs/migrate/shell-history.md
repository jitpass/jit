---
title: Migrating shell history
description: Credentials recorded in ~/.zsh_history move to the vault and each occurrence is redacted in place; jit guard history stops the next one being recorded at all.
---

# Shell history

A credential reaches your history file by being *typed*. That makes it the
one exposure every other scanner misses: it is not in a file whose name or
format says "credentials live here", it is in the middle of a `curl` command
you ran once in March. It also makes it durable in a way people
underestimate - history files are append-only in practice, get swept into
Time Machine, and are routinely committed to dotfile repos.

`jit scan` reports these as **Shell History** findings, with the line number.
`jit migrate ~/.zsh_history` (category `history`) is the fix:

```sh
jit scan ~/.zsh_history              # what's in there, with line numbers
jit migrate ~/.zsh_history --dry-run # preview
jit migrate ~/.zsh_history           # vault + redact
```

Each distinct credential value moves into the vault under a profile named
after the file (`zsh_history`), and **every occurrence** of it in the file is
replaced by a marker naming the entry that now holds it:

```
: 1782826756:0;curl -H 'Authorization: token <jit:redacted:GITHUB_PERSONAL_ACCESS_TOKEN>' https://api.github.com/user
```

The command line survives - you can still read your own history and see what
you ran - and so does every other byte of the file. jit splices out the
credential's bytes and copies the rest verbatim, so zsh's timestamp format
and metafied high bytes, bash's `HISTTIMEFORMAT` stanzas, and fish's YAML
round-trip exactly rather than being re-serialized.

Recover a redacted value with `jit vault get zsh_history/<VAR>`, or put the
whole file back with [`jit migrate undo ~/.zsh_history`](./undo-and-remove.md)
- an encrypted byte-exact backup is taken before anything is written.

## Rotation is still the fix

Redaction clears the *recorded copy*. It does not un-expose a value that has
already been written to disk in plaintext, possibly for months, and quite
possibly into a backup or a dotfiles repo you no longer control. Rotate the
credential at its provider; treat the redaction as the cleanup that stops it
being found again, not as the remedy.

That is why a history finding carrying a **production** indicator stays in
`jit scan`'s "only you can protect these" section rather than being offered
as a migrate: for a production credential, a command that tidies the file
would be answering the wrong question.

## Open shells can bring a line back

zsh and bash hold their history in memory and write it out on exit - a
default-configured zsh rewrites `$HISTFILE` wholesale when the shell closes.
So a shell that was already open when you ran the migration can resurrect the
lines jit just redacted.

After migrating, in each shell that was already open:

```sh
fc -R          # zsh: reload the redacted file into this session
history -r     # bash equivalent
```

or simply close them. Then re-run `jit scan` to confirm nothing came back.
If something did, run the migration again: a value jit has already vaulted is
re-redacted into the *same* vault entry, so a re-run is safe and produces no
duplicates.

jit also protects you inside the run itself. If a shell appends to the
history file while the migration is waiting on your Touch ID prompt, those
commands are preserved rather than overwritten; and if a credential jit has
not vaulted appears in that window, the run refuses and writes nothing rather
than half-redacting the file.

## Private keys are reported, never redacted

If you paste a private key at the prompt - a heredoc into `deploy_key`, an
`ssh-add` from a here-string - the key lands in your history like anything
else. `jit scan` reports that as **critical**, and `jit guard history` blocks
it from being recorded in the first place.

`jit migrate` deliberately will not touch it, and says so rather than
quietly doing nothing. What jit matches is the `-----BEGIN … KEY-----`
header; the key body is on the lines around it. Redacting the header would
leave the key sitting in the file while making the file look cleaned, which
is worse than leaving it alone visibly. There is also nothing useful to
vault: a header is public knowledge.

The remedy is the one no command can perform for you - regenerate the key,
replace it wherever it is authorized, then delete those lines by hand.

## What jit refuses to do

- **A symlinked history file.** The rewrite lands via rename, which replaces
  the path - the link's target (usually a dotfiles working copy) would keep
  every credential while jit reported success. Name the real file instead.
- **A hard-linked one**, for exactly the same reason: the other name would
  still hold the original bytes.

In both cases `jit scan` would afterwards read clean, because it only knows
the history file's own name. A silent all-clear is the one outcome this
command must never produce.

## Stopping the next one

Cleaning up is second best. jit offers the guard in two places rather than
making you find it: `jit scan` names it under any shell-history finding, and
bare `jit migrate` includes it in the plan it asks you to confirm (only when
the scan actually found a credential in your history, only on zsh, and only
if it is not already installed). You can also install it directly:

```sh
jit guard history            # install (writes ~/.jit/guard.zsh + one ~/.zshrc line)
jit guard history --remove   # reverse both
```

After that, a command jit recognizes as carrying a credential stays on that
session's history list - up-arrow still works, your flow is unbroken - but is
never written to `$HISTFILE`. jit prints one line saying so, naming the
format it matched.

The hook is built to stay out of your way, and the numbers are worth stating
plainly rather than rounding to "free". A pure-zsh test settles an ordinary
command in about 15 microseconds without launching anything. A line that could
hold a credential runs the real check instead, which costs about 33
milliseconds; on a real 592-command history that is 14% of lines, mostly
because any address with an `@` and any ten-character word qualify.

It reads the line over stdin rather than as an argument, so the value never
appears in `ps` output, and it is deliberately kept out of the
[audit log](../reference/plumbing.md). If jit is missing, errors, or takes
longer than two seconds, the hook fails **open** and the line saves normally:
silently eating your history would be a worse bug than missing a token, and a
hook that can hang is one that can freeze your shell.

If you set `$ZDOTDIR`, the source line goes in `$ZDOTDIR/.zshrc`, which is the
file your zsh actually reads.

zsh only, deliberately: it is macOS's default shell and the only one with a
clean pre-write hook. bash has no equivalent seam.
