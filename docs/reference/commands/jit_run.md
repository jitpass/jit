## jit run

Execute a command with a profile's secrets injected into its environment

### Synopsis

jit run decrypts every secret a profile references and replaces the jit
process entirely with the target command (execve), jit itself is gone
from memory the instant the target starts. The target process still holds
the plaintext once running: jit narrows the exposure window, it doesn't
sandbox what the target does with it.

Without --profile, jit resolves the project's migrated .env layers (looking
upward from the current directory, like git) and injects their merged
result in dotenv order, .env overridden by .env.local, printing exactly
what it merged. --mode <m> additionally layers .env.<m> and .env.<m>.local
in (.env < .env.<m> < .env.local < .env.<m>.local); a mode layer is never
merged without being asked for. --profile names one profile verbatim and
disables merging entirely.

The -- separating jit's own flags from the command is optional, jit stops
reading its flags at the first non-flag argument, so `jit run npm start`
works (jit's flags, if any, come before the command).

```
jit run [--profile <name>] [--mode <mode>] [--] <command> [args...] [flags]
```

### Examples

```
  jit run -- npm start
  jit run --mode production -- npm start
  jit run --profile aws-admin -- terraform plan
```

### Options

```
      --mode string      also merge .env.<mode> and .env.<mode>.local layers (e.g. production)
      --profile string   profile to inject verbatim (default: merge this project's migrated .env layers)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

