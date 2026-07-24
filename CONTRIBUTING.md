# Contributing to jitpass

Thanks for your interest in `jit`. This project is in early development and
maintained part-time by a single person, so please read this before opening a
large PR, a quick issue to align on approach first saves everyone time.

## Ground rules

- **Sign off your commits (DCO, not a CLA).** Every commit must carry a
  `Signed-off-by:` line certifying the [Developer Certificate of
  Origin](https://developercertificate.org/). Add it automatically with:

  ```sh
  git commit -s
  ```

  By signing off you assert you have the right to submit the work under the
  project's [PolyForm Perimeter 1.0.0](./LICENSE) license. There is no CLA.

- **License.** The project is licensed under the PolyForm Perimeter License
  1.0.0, a source-available license (see [LICENSE](./LICENSE)); it does not
  convert to an open-source license. All contributions are made under those
  same terms. Don't paste in code under a license incompatible with this
  arrangement (for example, copyleft code).

- **Security issues are not regular PRs.** If you've found a vulnerability, do
  **not** open a public issue or PR, follow [SECURITY.md](./SECURITY.md) for
  private reporting.

## Before you start

- Read the [security architecture](./docs/security/architecture.md) for the
  explicit threat-model boundaries (what jit deliberately does *not* defend
  against). A change that
  "fixes" a documented boundary may be changing the design on purpose; open
  an issue to discuss first. (Code comments cite the full design docs, RFC
  sections, `GAPS.md #NN`, which are maintained in a private planning repo;
  if a change hinges on one, ask in the issue and we'll quote the relevant
  part.)
- Each `internal/*` package has a `doc.go` with the reasoning behind the code
  and pointers to the relevant design docs. Read it before changing a package,
  a lot of non-obvious behavior is deliberate.

## Development

Requires Go 1.26+ and macOS (a few packages are darwin-only CGo:
`internal/secureenclave`, `internal/keychainwrap`, `internal/lineage`).

```sh
go build ./...
go vet ./...
go test -race ./...            # the full suite runs without Touch ID
staticcheck ./...
govulncheck ./...
gosec ./...
```

CI runs all of the above on `macos-latest`. Please make sure they pass locally
before opening a PR.

### Testing conventions worth knowing

- **The test suite never touches your real vault, keychain, or `$HOME`.** This
  isolation is not optional, the rules exist because of real incidents (a test
  once migrated live config on the machine running the suite; another was one
  cleanup step from deleting a real vault's master key). Any test on a path
  reachable from real `jit migrate` must isolate **both** the working directory
  and `$HOME`, copy the fixture-home/fixture-cwd pattern the existing tests
  in `internal/cli` and `internal/migrate` use.
- **Anything requiring an interactive Touch ID/passcode prompt cannot be tested
  automatically**, those paths are stubbed in tests and verified manually
  against a throwaway fixture `$HOME`. Never point a test at the production
  keychain identifier.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Include tests for behavior changes where the path is testable without an
  interactive prompt.
- Describe *why*, not just *what*, link the relevant RFC/GAPS item if there is
  one.
- Make sure `git commit -s` sign-off is present on every commit.

## Adding a `jit wrap` plugin

The lowest-friction contribution in the repo: teaching `jit wrap` (and
`jit scan`) about another CLI's token is one data block in
`internal/wrap/catalog_data.go`, one sanitized config sample in
`internal/wrap/testdata/<tool>/`, a row in
`internal/wrap/catalog_test.go`'s fixture table, a row in
[docs/wrap/index.md](./docs/wrap/index.md), and a
[docs/wrap/](./docs/wrap/) page for the tool - no logic. Tests enforce all
of it: malformed entries fail `TestCatalogEntriesAreWellFormed`, and an
undocumented tool fails the wrap-docs drift guard. In the PR, link the
tool's own docs for where it stores its credential and which env var it
reads (that's what review checks - see
[docs/internal/WRAP-PLAN.md](./docs/internal/WRAP-PLAN.md) §3.2 for how the
shim-vs-native kind is chosen).

## Scope

Only `cmd/` and `internal/` are production code. Everything under `spike/` is
throwaway/exploratory, read its `FINDINGS.md` before assuming a spike reflects
how the real code works.
