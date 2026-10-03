## jit az-run

Run the Azure CLI with its login unsealed for that one run

### Synopsis

Not typically run by hand: the shim `jit wrap az` installs execs this around
every az invocation. The Azure CLI's login (its token cache and service
principal secrets) lives in the vault; this unpacks it into a private
folder for the one run, points az at it with AZURE_CONFIG_DIR, and seals it
again afterwards if the run changed it (a refresh, a login, a logout),
merged with any change another az run sealed meanwhile. Your settings stay
in ~/.azure. The tool's exit status is passed through unchanged.

```
jit az-run --real <path> -- [args] [flags]
```

### Options

```
      --real string   absolute path to the real tool (supplied by the shim)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

