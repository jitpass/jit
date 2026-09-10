# The minting broker: reviewed and narrowed

**Status:** reviewed 2026-09-07 and NARROWED. The original draft (2026-09-07,
same day) proposed that jit mint short-lived credentials itself, speaking
STS and OAuth at the seams. A three-way review (code verification against
`internal/agent`/`awscred.go`/wrap/vault/audit, external-claims research,
and an adversarial pass) changed the decision:

- **Build now:** gcloud store detection (part A below). Closes issue #93.
- **Rejected:** the AWS assume-role mint. Recorded in part C so it is not
  re-proposed.
- **Deferred, not killed:** the gcloud mint (part B), until an outside
  user asks for it. The design is recorded with the review's corrections
  folded in, so reviving it starts from facts, not from the first draft.

Companions: `internal/cli/clissocapture.go:37-45` (the best in-tree
statement of capture vs mint), `internal/audit/derived.go:12-27` (the
derived-credentials boundary), `design/migrate-clean.md` (backup/undo
machinery part A's future migrate would reuse).

## Why the full broker lost the review

1. **It reverses published security promises, not internal habits.**
   `docs/security/brief.md:19` says "Nothing is added to the network
   surface"; `brief.md:156-162` says "no secret, path, or scan result is
   ever transmitted." An OAuth mint POSTs the vaulted refresh token
   itself to the token endpoint: the flagship claim becomes flatly
   untrue. `docs/why-jit.md` promises "works fully offline." The
   derived-credentials boundary is also stated to reviewers in
   `docs/security/architecture.md` as a deliberate limit. A feature that
   requires rewriting the security brief is a strategy change, and
   demand for it is currently zero outside issues (#93, self-filed, asks
   for detection).
2. **"Always clean" was overstated.** An env-injected access token is
   readable by any same-user process for the child's lifetime
   (KERN_PROCARGS2) and inherited by grandchildren. The honest invariant
   is *no plaintext at rest*, and against that weaker claim the rejected
   ephemeral-store variant nearly ties while costing zero network
   surface. The draft rejected it against an invariant the draft itself
   did not meet.
3. **Destructive migrate plus shim delivery invents a new failure
   class.** Every shipped migrate leaves the file working. Deleting
   gcloud's store makes any shim bypass (absolute path, cron, IDE PATH,
   SDK-internal invocations) mean *broken tool*, not *unprotected
   file*. No shipped jit feature has that failure mode.
4. **The repo already chose the opposite pattern once, by name.**
   `TECH_STACK.md` records rejecting the 1Password SDK in favor of
   exec'ing the user's own `op` binary: the vendor's signed code speaks
   the vendor's protocol. The draft never evaluated the equivalent
   (exec `gcloud auth print-access-token`) before proposing a hand-
   rolled OAuth client jit must keep correct against Google's
   undocumented reauth behavior forever. The support treadmill is the
   notarization saga's shape, times two providers, permanently.
5. **The prize was small on the AWS side.** Verified: the AWS CLI never
   disk-caches credential_process output, but a `role_arn` profile
   chaining off it STILL writes the assumed session to
   `~/.aws/cli/cache` (botocore `JSONFileCache`, CLI-only). Preventing
   that write means rewriting the user's role profiles in
   `~/.aws/config`, a file boto3 and terraform also interpret. The win
   would be deleting a self-expiring 1h cache that `derived.go` already
   reports with deletion advice. Nobody asked.

## Part A. Ship now: gcloud store detection

Scan-only, zero dependencies, no new mechanism. Verified facts: the
store is SQLite, table `credentials(account_id TEXT PRIMARY KEY, value
BLOB)`, the blob is plain JSON carrying `refresh_token` (the secret;
the client_id/client_secret beside it are gcloud's public installed-app
constants, the position `gcpadc.go:25-32` already takes and the finding
prose should state).

- `scanGcloudCLICredentials(cfg)` in `internal/audit/credfile.go`,
  appended at `credfile.go:57-70`: fixed paths (`credentials.db`,
  `access_tokens.db`, `legacy_credentials/`), the standard
  Lstat/IsRegular guard, `openFile`, then locate the serialized
  credential in the raw bytes the way `gcpADCValuePattern` does
  (`internal/migrate/gcpadc.go:52-63`, a regex over raw file bytes).
  NOT the `agentcache.go` technique: that is fixed-string matching of
  already-known values and is structurally blind here.
- A `selfRotatingCaches` entry (`selfrotating.go`) so the remedy is
  manual, `FixCommand` stays empty, and scan never promises a migrate
  it cannot perform. Permanent until part B ships, if it ever does.
- Add `.db` to `credentialDumpSkipExts` (`content.go:62-68` has only
  `.sqlite`), so the content sweep stops reading DB binaries for
  nothing.
- Fix `docs/migrate/gcp.md:57-58`, which currently frames the gap as
  intentional; after this it is a reported finding.
- Extend the derived-credentials advisory to name the gcloud store
  family alongside the AWS caches.

## Part B. Deferred: the gcloud mint (recorded option)

Revive only on outside demand. If revived, the review's corrections are
binding; the first draft's version of these sections is superseded.

**B1. Evaluate exec-the-vendor before a hand-rolled client.** The `op`
precedent says: materialize the store into a temp `CLOUDSDK_CONFIG`,
run `gcloud auth print-access-token` (Google's code does reauth, RAPT,
rotation), capture stdout, shred the dir, inject the token. Sub-second
plaintext window during the mint only. Caveat recorded: Google labels
`print-refresh-token` (not `print-access-token`) an internal detail;
verify stability in the spike. Only if this fails does the stdlib OAuth
client get considered, under the rules in B4.

**B2. Where the code actually lives.** `internal/agent` cannot resolve
secrets: it never imports `internal/vault` by doctrine
(`agent/doc.go:13-16`, `server.go:180-182`) and sees only opaque DEK
bytes. A mint is therefore a new `Server.OnMint` callback wired from
`internal/cli/servicerun.go` (the `OnResolveGrant` pattern,
`grant.go:460-505`), likely backed by a new `internal/mint` package.
The mint cache must be agent-side because `credential_process` forks a
fresh jit per invocation; that means a new RPC in which the agent
returns derived secret material over the socket for the first time
(today `Response.Data` carries only wrapped/unwrapped DEKs), a
`Protocol` bump, and a defined no-agent fallback.

**B3. Gates the draft omitted, found in review:**
- **Consent:** `gateConsent` fires only from `OpUnwrap` (`server.go:631`).
  A mint op must gate itself or it is a consent bypass handing out a
  derived credential of the same power with no prompt. The new OAuth
  class must join `consent/policy.go`'s classified lists (build-enforced).
  Prompt wording must be agent-derived, never caller-supplied
  (`protocol.go:75-89`).
- **Vault shape:** decide `Storage` marker (dispatch-bearing, AAD-bound,
  the op-ref pattern; `design/1password-adapter.md:73-77` forbids
  sniffing) versus `Class` (provenance only). Envelope is v5 and
  `Meta.ExpiresUnix` already exists and is honored on rotation writes
  (`vault.go:136-151`); do not reinvent expiry metadata.
- **Audit:** new `SessionEvent` fields for endpoint/expiry (`Labels` is
  caller-reported and rendered as claimed, wrong for agent-resolved
  facts), a rendering case in `internal/cli/audit.go:886` (the switch's
  default renders unknown kinds as a fake "session unlocked"), and
  KindServe-style collapsing (`protocol.go:256-262`) so a gcloud loop
  cannot evict real history from the 200-event ring.
- **Lock semantics:** decide whether the mint cache survives screen lock
  when riding a process grant (grants deliberately survive,
  `session.go:765-771`); use the generation-counter idiom for a mint in
  flight across a lock. Minted values get `wipe()`, not just nil.
- **Concurrency:** no singleflight dependency; the house pattern is a
  dedicated mutex (`challengeMu`, `server.go:250`). A mint does network
  I/O, so it must not sit on `s.mu` (the documented `grantMu` rule).
- **Wrap kind `mint`:** there is no exhaustive-switch lint; the full
  edit list is `shimArgv` (`shim.go:148-163`), `wrapPlanDetail`
  (`cli/migrate.go:345-361`, prints an empty consent line otherwise),
  `manifest.go` Entry + `IsMint()`, `undo.go:70,116`,
  `wrap/doctor.go:120-140`, `cli/wrap.go:99,126,155,467-473`,
  `audit/wrapcli.go:37`, `docs/wrap/gcloud.md` (build-enforced by
  `plugins_doc_test.go`), and the "four kinds" prose in `CLAUDE.md:71`
  and `wrap/doc.go:16`.
- **Docs that must change or the feature lies:** `docs/security/
  brief.md:19,156-162`, `docs/why-jit.md:139-146,193-195`,
  `docs/security/architecture.md` deliberate-limits, TECH_STACK (a
  network-surface section, reconciled with the existing §2.12
  webhook plan).

**B4. If a stdlib OAuth client is ever written:** never retry
`invalid_grant` (RFC 6749 §5.2; Google's library treats it as
terminal; surface Google's `error_subtype: invalid_rapt` to
distinguish session policy from revocation); retry only
5xx/`temporarily_unavailable` with jittered backoff, honor 429
Retry-After; persist a rotated refresh token atomically before
treating the refresh as complete (RFC 9700 §4.14.2: replaying a
rotated-out token can revoke the whole grant); validate `token_uri`
against a pinned allowlist before use (Google documents exactly this
for externally-sourced credentials) and note the default transport
honors `HTTPS_PROXY`, so the allowlist needs a decision about proxies.
Refresh-timing prior art: botocore's advisory/mandatory two-threshold
model, aws-sdk-go-v2's jittered expiry window, x/oauth2's 10s skew
delta.

## Part C. Rejected: the AWS assume-role mint

Rejected 2026-09-07; do not re-propose without new facts. Reasons: the
only artifact it removes is `~/.aws/cli/cache`, which self-expires and
is already reported; preventing the write requires rewriting user
`role_arn` profiles that other SDKs read; hand-rolled SigV4 is
security-critical signing code in-tree forever; and `awscred.go:117-127`
already fails loud on expiry with the exact re-mint command, a shipped
UX the mint would have contradicted. If it ever returns, the SigV4
facts are: Query API `Version=2011-06-15` is frozen, regional endpoints
(`sts.{region}.amazonaws.com`) are the documented best practice,
`encoding/xml` suffices (minio-go is the existence proof), and AWS's
own UriEncode warning applies to Go's `url.Values.Encode`.

## Standing doctrine (unchanged by the narrowing)

- A DB token store is never mounted and never templated. FIFO-serving
  SQLite is structurally infeasible (seeks, byte-range locks) and
  gcloud writes to its store (`selfrotating.go:16-22`).
- Watch-in-place is not protection: an unentitled process cannot see or
  block reads on macOS, only writes. It is a synchronized backup.
- EndpointSecurity/Santa-style file-access authorization stays rejected
  for jit's bare-binary shape (`internal/mount/doc.go:19-26`).
- Capture vs mint taxonomy: a derivation is mintable iff its input is a
  vaulted secret; human ceremonies (SAML, browser login, MFA) are
  captured, never repeated by jit.
