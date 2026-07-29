## jit clisso-capture

Run clisso, capturing minted AWS credentials into the vault

### Synopsis

Not typically run by hand: the shim `jit wrap clisso` installs execs this
around every clisso invocation. A `clisso get` runs with clisso's own
--output credential_process flag and the minted credentials are stored in
the vault (profile aws-<app>, served back via credential_process) instead
of written to ~/.aws/credentials in plaintext. Every other invocation
passes through to the real clisso unchanged.

```
jit clisso-capture --real <path> -- [clisso args] [flags]
```

### Options

```
      --real string   absolute path to the real clisso binary (supplied by the shim)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

