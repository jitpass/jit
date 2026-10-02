## jit gcloud-run

Run a Google Cloud CLI with its login unsealed for that one run

### Synopsis

Not typically run by hand: the shims `jit wrap gcloud` installs (gcloud, bq,
gsutil, docker-credential-gcloud, git-credential-gcloud) exec this around
every invocation. gcloud's login store lives in the vault; this unpacks it
into a private folder for the one run, points the tool at it with
CLOUDSDK_CONFIG, and seals it again afterwards if the run changed it (a
login, an activate, a revoke). Your settings stay in ~/.config/gcloud.
The tool's exit status is passed through unchanged.

```
jit gcloud-run --real <path> -- [args] [flags]
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

