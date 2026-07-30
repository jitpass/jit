## jit upgrade

Download the latest release, verify it, and swap this binary + service onto it

### Synopsis

Upgrades jit in place: fetches the latest published release, verifies its
SHA-256 against the release's checksums.txt, replaces the running jit binary,
and restarts the background service so it's immediately on the new build (no
waiting for the stale-binary poll).

Replaces the binary `jit` actually runs from (whatever `which jit` resolves to).
If that path isn't writable (e.g. /usr/local/bin), you'll be prompted for sudo
just for the move. Your vault and secrets are never touched.

A Homebrew-installed jit is not self-replaced — Homebrew owns that copy, so
this command points you at `brew upgrade --cask jitpass` instead.

Only the published darwin/arm64 release is fetched this way; on any other
platform, build from source with `go install github.com/jitpass/jit/cmd/jit@latest`.

```
jit upgrade [flags]
```

### Options

```
      --force   reinstall the latest release even if it matches the current version
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

