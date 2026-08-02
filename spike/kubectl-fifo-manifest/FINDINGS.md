# Spike Findings: kubectl vs FIFO-mounted Secret manifests (rejectable decoys)

**Questions:** (1) Does `kubectl apply -f <path>` read a named pipe, and how many
times does one invocation open it? (2) Does the jit decoy manifest (`data:`
values of `jit-hidden-<VAR>`, never valid base64) fail loudly under a real
apply? Client-side or server-side? (3) Does a `stringData:` decoy slip through
silently? These are the load-bearing assumptions of the k8s Secret-manifest
migration plan (k8s protection plan item 4).

**Environment:** macOS 26.5.0 arm64, Go 1.26.5, kubectl v1.36.3 (Homebrew).
No cluster and no Docker on the machine; real `kubectl apply` (not `--dry-run`)
was exercised against this spike's mock apiserver: core-v1 discovery plus a
secrets endpoint whose write handler decodes into `Data map[string][]byte`,
which is the same encoding/json `[]byte` typed decode that produces the real
apiserver's "illegal base64 data" rejection. Everything else about the mock is
fake; the decode semantics are the part under test.

## Result summary

| Case | Outcome |
|---|---|
| Valid manifest, regular file, real apply | `secret/db-creds created`, exit 0 |
| Decoy manifest (`data: jit-hidden-*`), real apply | **`Error from server (BadRequest): ... illegal base64 data at input byte 3`, exit 1** |
| `stringData:` decoy, real apply | **Silently accepted**; stored value is literally `jit-hidden-SECRET_DB_CREDS_PASSWORD` |
| Decoy, default `--validate=strict`, openapi unavailable | Fails loudly at validation download, exit 1 |
| Valid manifest served over FIFO, real apply | `created`, exit 0, **exactly 1 open/serve cycle** |
| Decoy served over FIFO, real apply | Same loud base64 rejection, exit 1, exactly 1 cycle |

## kubectl reads a FIFO, and opens it exactly once

`kubectl apply -f <fifo>` works end to end: the file visitor opens the pipe,
reads to EOF, parses, and proceeds. One invocation = one open. The serve loop's
write completed in full (120 and 253 bytes) with no write or close errors, at
~75ms after server start. Nothing in kubectl stats the file for size first or
mmaps it. The FIFO delivery design is confirmed; no swap-mode fallback needed.

## The phantom-16-opens lesson: recreate-after-close is not optional

The first version of this spike's serve loop did open -> write -> close ->
reopen, without recreating the FIFO, and counted 16 "opens" for a single
kubectl run: while the reader still held the old read end, the server's next
`open(O_WRONLY)` succeeded instantly against the same pipe and wrote the
payload again. `internal/mount.Serve`'s recreate-by-rename step
(mount.go `recreateFIFO`) is exactly what prevents this; with the
mkfifo-at-sibling + rename-over step replicated here, the count is a clean 1.
Any future serving code that skips the recreate will double-serve content to a
slow reader. The production loop already does this correctly.

## The decoy rejection is real, but it is server-side in modern kubectl

`jit-hidden-<VAR>` contains `-`, which is outside the base64 alphabet, so the
decode always fails. But kubectl v1.36 does NOT decode `data:` client-side: the
mock's request log shows the POST arriving with the raw decoy string, then the
400. The older GitHub-issue evidence of client-side rejection (#31548) is from
pre-unstructured kubectl; do not claim "fails offline before any network call"
in docs. What is true and verified:

- With a reachable cluster: the apiserver rejects at typed decode, kubectl
  exits 1 with `illegal base64 data`, and nothing is stored.
- Without a reachable cluster: apply fails even earlier (discovery/openapi),
  also loudly.
- There is no configuration in which the decoy is silently applied, which is
  the guarantee the feature needs. `--validate=false` changes nothing about it.

One caveat carried over from the docs research still holds: values that happen
to be valid base64 would be accepted as garbage bytes, so decoys must always
contain an out-of-alphabet character. `jit-hidden-` guarantees this by
construction; a test in the real implementation should assert it.

## stringData is confirmed as the silent-failure hazard

The `stringData:` decoy applied cleanly and the literal string
`jit-hidden-SECRET_DB_CREDS_PASSWORD` became the stored secret value. This is
the empirical proof behind the migration decision to convert `stringData:`
keys into `data:` at migrate time: only `data:` gives the rejectable-decoy
property.

## Implications for the implementation plan

1. FIFO template mount is the right delivery; kubectl needs no special casing
   (`commandReadsEnvFile` swap fallback not required for kubectl).
2. Keep the decoy content as `DecoyNotice()` + `jit-hidden-*`: the `#` header
   is valid YAML, so the failure lands precisely at the base64 decode with a
   clear error naming the manifest path.
3. Convert `stringData:` to `data:` during migration, without exception.
4. Docs wording: say "kubectl refuses to apply the decoys" and "the API server
   rejects them", not "fails before leaving your machine".
