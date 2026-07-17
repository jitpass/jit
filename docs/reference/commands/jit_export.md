## jit export

Print shell export statements for a profile's secrets

### Synopsis

jit export decrypts every secret a profile references and prints POSIX
shell `export VAR='value'` statements to stdout, meant to be evaluated
into the current session. Nothing is written to disk or to any shell init
file, the values live only in this one shell session's environment.

Profile selection works exactly like jit run's: without --profile, jit
resolves the project's migrated .env layers (looking upward from the
current directory) and exports their merged result in dotenv order,
.env overridden by .env.local, announcing what it merged on stderr, so
eval never swallows it. --mode <m> layers .env.<m>/.env.<m>.local in;
--profile names one profile verbatim and disables merging.

```
jit export [--profile <name>] [--mode <mode>] [flags]
```

### Examples

```
  eval "$(jit export)"
  eval "$(jit export --profile aws-admin)"
```

### Options

```
      --mode string      also merge .env.<mode> and .env.<mode>.local layers (e.g. production)
      --profile string   profile to export verbatim (default: merge this project's migrated .env layers)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

