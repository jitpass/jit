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

When the service is running and unlocked, jit run also makes this run's
mounted files compatible with the command reading them, for the run's
lifetime only. By default it swaps each mount to a plain inert pointer
file, so `[ -f .env ]`/is_file() guards pass and re-reading the file
sets nothing (the real values are in the environment). --live instead
keeps the live mount and grants this run's process tree real file reads,
for tools that read values from the .env file itself (docker compose
env_file), which jit run also auto-detects. Either way the mount returns
to its decoy state the moment the command exits; no service, or a locked
one, skips this silently and injection works the same regardless.
A project whose tools always read the file itself can pin live mode by
putting `read_as_file: true` in its .jit/config.yaml, instead of --live
on every run.

--with names a global, file-delivered credential to grant this run:
gcp (gcloud ADC), sops, npm (~/.npmrc), or netrc (~/.netrc), for a tool
that reads a machine-wide credential file, e.g. `jit run --with gcp
terraform apply`.
It takes explicit intent by design: a global credential is never
granted by a project's config, only by a --with you type.

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
      --live                                        keep the live mount and grant this run real file reads, for tools that read values from the .env file itself (docker compose env_file); default swaps in a compatibility file
      --mode string                                 also merge .env.<mode> and .env.<mode>.local layers (e.g. production)
      --profile string                              profile to inject verbatim (default: merge this project's migrated .env layers)
      --trust                                       pre-authorize this run's whole process tree for any credential, so per-process consent prompts don't fire under it
      --with jit run --with gcp gcloud storage ls   also grant this run a global file-delivered mount by name (gcp, sops, npm, netrc) - for tools that read a machine-wide credential file, e.g. jit run --with gcp gcloud storage ls (repeatable)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

