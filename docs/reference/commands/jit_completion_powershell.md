## jit completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	jit completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
jit completion powershell [flags]
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

