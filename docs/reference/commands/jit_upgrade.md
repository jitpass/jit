## jit upgrade

Download the latest release, verify it, and swap this binary + service onto it

### Synopsis

Upgrades jit in place: fetches the latest published release, verifies its
SHA-256 against the release's checksums.txt AND its Developer ID signature,
replaces the running jit binary, and restarts the background service so it's
immediately on the new build (no waiting for the stale-binary poll).

Both checks must pass. The checksum proves the download wasn't corrupted;
the signature proves it came from us, since checksums.txt is served from the
same place as the archive. Neither can be skipped.

Replaces the binary `jit` actually runs from (whatever `which jit` resolves to).
If that path isn't writable (e.g. /usr/local/bin), you'll be prompted for sudo
just for the move. Your vault and secrets are never touched.

A jit installed by Homebrew is not self-replaced, since Homebrew owns that
copy — run `brew upgrade jitpass` instead. Reinstall from the release
tarball if you would rather this command manage it, so
switch to a self-upgrading build (see the install guide).

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

