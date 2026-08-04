## jit guard history

Keep typed credentials out of your shell history file (zsh)

### Synopsis

jit guard history installs a zsh hook that checks every command line for a
known credential format before zsh writes it to the history file. A command
carrying one stays on the SESSION's history list — up-arrow keeps working —
but is never written to $HISTFILE, so it cannot end up in Time Machine
backups or a dotfiles repo, and `jit scan` never has to find it.

The check is two-stage so it costs nothing at the prompt: a pure-zsh test
(the same admit conditions jit scan's history prefilter uses) passes ~95%
of commands untouched, and only a line that could hold a credential runs
the real vendor patterns via jit itself — over stdin, never argv, so the
value never appears in ps output. If jit is missing or errors, the hook
fails OPEN and the line saves normally: eating history would be worse.

zsh only, deliberately: zsh is macOS's default shell and the only one with
a clean pre-write hook (zshaddhistory). What it installs: ~/.jit/guard.zsh
plus one source line in ~/.zshrc; --remove reverses both exactly.

```
jit guard history [flags]
```

### Examples

```
  jit guard history            # install the hook
  jit guard history --remove   # remove it
```

### Options

```
      --remove   remove the guard: delete the hook file and take the source line out of ~/.zshrc
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit guard](jit_guard.md)	 - Prevention hooks that keep credentials from being recorded in the first place

