## jit guard history

Keep typed credentials out of your shell history file (zsh)

### Synopsis

jit guard history installs a zsh hook that checks every command line for a
known credential format before zsh writes it to the history file. A command
carrying one stays on the SESSION's history list, so up-arrow keeps working,
but is never written to $HISTFILE. It cannot end up in a Time Machine backup
or a dotfiles repo, and `jit scan` never has to find it.

The check is two-stage, so most commands cost nothing measurable: a
pure-zsh test (the same admit conditions jit scan's history prefilter
uses) settles a line in about 15 microseconds without launching anything.
Only a line that could hold a credential runs the real vendor patterns via
jit itself, which costs about 33 milliseconds. On a real 592-command
history that second path takes 14% of lines, mostly because any address
with an @ and any ten-character word qualify.

That check reads the line over stdin, never argv, so the value never
appears in ps output. It is also bounded: if jit is missing, errors, or
takes longer than two seconds, the hook fails OPEN and the line saves
normally. Silently eating your history would be a worse bug than missing
a token, and a hook that can hang is a hook that can freeze your shell.

zsh only, deliberately: zsh is macOS's default shell and the only one with
a clean pre-write hook (zshaddhistory). What it installs: ~/.jit/guard.zsh
plus one source line in ~/.zshrc (or $ZDOTDIR/.zshrc when that is set);
--remove reverses both exactly.

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
      --dry-run   preview what installing (or --remove: removing) the guard would do without changing anything
      --remove    remove the guard: delete the hook file and take the source line out of ~/.zshrc
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit guard](jit_guard.md)	 - Prevention hooks that keep credentials from being recorded in the first place

