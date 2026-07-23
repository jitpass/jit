## jit completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(jit completion zsh)

To load completions for every new session, execute once:

#### Linux:

	jit completion zsh > "${fpath[1]}/_jit"

#### macOS:

	jit completion zsh > $(brew --prefix)/share/zsh/site-functions/_jit

You will need to start a new shell for this setup to take effect.


```
jit completion zsh [flags]
```

### Options

```
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit completion](jit_completion.md)	 - Generate the autocompletion script for the specified shell

