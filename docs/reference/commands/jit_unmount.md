## jit unmount

Reverse a live .env mount back into a plain file

### Synopsis

jit unmount decrypts a mounted .env's secrets from the vault and writes
them back out as a plain file at the same path, replacing the live-mounted
pipe jit migrate created. The vault secrets and the profile manifest are
left in place, only the physical mount is reversed.

If jit agent is running, this stops serving just this one mount first, so
nothing races the file being replaced, every other mount keeps being
served undisturbed.

```
jit unmount <path> [flags]
```

### Options

```
  -y, --yes   skip the confirmation prompt and unmount immediately
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

