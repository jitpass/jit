# Findings: download-redirect Worker (dl.jitpass.com)

**Question.** GitHub's release API exposes exactly one number about downloads
(`download_count`, cumulative, no who/when/where — verified against the full
asset field list, and the org audit log neither covers public downloads nor
exists below Enterprise). Can a one-hop redirect through a host we own give
real per-download data — client type, version, country — without touching the
binary, the bytes, or the signature chain?

**Answer: yes.** 12/12 local checks pass (`test.sh`, wrangler v4 dev, no
Cloudflare account needed). Worker is ~90 lines, logs one line, 302s to
GitHub, never proxies a body.

## What was proven

1. **Byte integrity is preserved through the redirect.** A tarball fetched
   via the Worker hash-matches the release's own published `checksums.txt`
   (v0.81.0, `bea735b7…`). The cask's `sha256` therefore stays a hash of
   GitHub's bytes; nothing about goreleaser's checksum flow changes.
2. **All three client classes separate cleanly by user-agent.**
   `Homebrew/…` → `brew`, `curl/…` → `curl`, and — the lucky find —
   `internal/cli/upgrade.go` already sets `User-Agent: jit-upgrade` on all
   three of its fetches (redirect page, checksums, tarball), so self-updates
   are distinguishable with zero binary changes.
3. **Country/colo come free** from `request.cf` (`country=IL colo=TLV` in the
   local run). No IP is logged — the log line and the Analytics Engine row
   carry client class, tag, asset, country, colo, and nothing else.
4. **The path allowlist holds.** Tag must match `^v\d+\.\d+\.\d+$`, asset must
   be one of the two shipped names; `evil.sh`, foreign repos, traversal
   encodings, and `/` all 404. The Worker cannot be used as an open
   redirector.
5. **HEAD also 302s** (brew probes with HEAD before fetching).

## Design decisions that should survive into production

- **Redirect, never proxy.** The worst failure mode must be "download fails
  loudly", never "different bytes served". A body-proxying worker would put
  us in the serving path for real; a 302 keeps GitHub as the only origin.
- **Log dimensions, not identities.** No IP, no full UA string. The privacy
  story has to survive being read aloud in a security review: "we count
  downloads by client type and country".
- **`jit upgrade` stays pointed at GitHub.** Instrument acquisition (the cask
  URL) only; the security-critical self-update path remains unmodified and
  unmeasured. The redirect host must never become load-bearing for
  `verifyStagedSignature`'s chain.

## What production needs that the spike does not

- A Cloudflare account + zone for jitpass.com; route `dl.jitpass.com/*` to
  the Worker; uncomment the `[[analytics_engine_datasets]]` binding
  (`DL_STATS` / `jit_downloads`) — Analytics Engine has no local emulation,
  so it is deploy-verified only. Queryable with SQL from the dashboard/API;
  free tier is ample at current volume.
- The cask `url` in `.goreleaser.yml`'s `homebrew_casks` block pointed at
  `https://dl.jitpass.com/jitpass/jit/releases/download/{tag}/…` (the Worker
  mirrors GitHub's path shape exactly so the template is a hostname swap).
- **Availability honesty:** the Worker becomes a hard dependency of
  `brew install`. Keep it dumb (log + redirect only), and know that rolling
  back is a one-line cask revert re-pointing at github.com.
- A retention line on the site ("aggregate download stats by client type and
  country; no IPs retained").

## Known limits

- New-asset names (e.g. a future darwin_amd64 tarball) must be added to
  `ASSET_ALLOW` or they 404 — a release checklist item, and the failure is
  loud (brew install errors), not silent.
- The `/latest/` route logs `tag=latest`, not the resolved version. Per-tag
  numbers come from the pinned-tag route the cask uses; `latest` is what
  curl-instruction users hit, and their version is resolved by GitHub after
  our hop. Acceptable: the cask (brew) and any pinned curl line carry tags.
- `wrangler dev --log-level warn` suppresses the Worker's `console.log`;
  use `--log-level log` (or `wrangler tail` in prod) to see classification
  lines. test.sh's section [5] is informational for this reason.
