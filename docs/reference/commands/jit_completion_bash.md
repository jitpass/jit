## jit completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(jit completion bash)

To load completions for every new session, execute once:

#### Linux:

	jit completion bash > /etc/bash_completion.d/jit

#### macOS:

	jit completion bash > $(brew --prefix)/etc/bash_completion.d/jit

You will need to start a new shell for this setup to take effect.


```
jit completion bash
```

### Options

```
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [jit completion](jit_completion.md)	 - Generate the autocompletion script for the specified shell

