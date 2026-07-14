// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Package migrate implements jit migrate: RFC.md's guided fix path for
// findings jit audit reports. A separate command from jit audit, not a
// flag on it, so audit's read-only guarantee holds under every flag
// combination (see internal/audit/doc.go and RFC.md's read-only note in
// §4).
//
// jit migrate local (.env/MCP/npmrc scoped to the current directory
// tree) and jit migrate home (the same three, scoped to anywhere under
// $HOME) both call this package's own Discover* functions directly for
// --dry-run's preview AND a real run's actual discovery — the same call,
// just a different root (cwd vs home) passed to it. This is deliberate
// (GAPS.md #26): an earlier design re-ran audit.Scan across the whole
// machine for --dry-run's preview while real mode's discovery was always
// narrower for three of six categories, so the preview and reality could
// silently disagree — .env's own plan text already carried a "real mode
// only walks the current directory tree" caveat, but MCP/npmrc's didn't,
// which is what made the gap visible in practice. Sharing one discovery
// call per scope is what makes that structurally impossible now.
//
// Real mutation covers seven finding types (GAPS.md #7, #8, and #16's
// Terraform half are closed):
//
//   - .env files (apply.go/unmount.go), scoped to the chosen root (cwd for
//     jit migrate local, $HOME for jit migrate home), converted into a
//     profile + vault secrets + a live-mounted pipe (RFC.md Pillar III
//     Tier 3, task #10) that jit unmount can reverse. A git-safe,
//     IDE-peekable <file>.pointers companion (pointerfile.go, GAPS.md #26)
//     is written alongside it — see that file's own doc comment for why,
//     including the just-in-time interception scheme that was considered
//     and rejected as infeasible on macOS without Endpoint Security.
//   - Shell configs (shellconfig.go): .zshrc/.bashrc/etc. under $HOME —
//     always checked regardless of the current directory, since these live
//     at a fixed home path either way. Secret-shaped export lines move
//     into the vault, replaced with a single `eval "$(jit export
//     --profile ...)"` call; the original file is backed up first.
//   - MCP configs (mcpconfig.go): Claude Desktop's global config, always
//     checked, plus mcp.json/.mcp.json under the chosen root. A server's
//     env-block secrets move into the vault; its command is rewritten to
//     launch via `jit run` instead, using jit's own resolved executable
//     path rather than a bare "jit" (a GUI-launched host's PATH often
//     doesn't match an interactive shell's). Backed up first too.
//   - AWS credentials (awscreds.go, RFC.md Pillar III Tier 2): a profile's
//     static keys move into the vault; ~/.aws/config gets a
//     credential_process line (under the correct "[default]" vs
//     "[profile <name>]" section — AWS's own irregular convention) that
//     invokes `jit aws-credential-process` instead. Both files backed up.
//   - kubeconfig (kubeconfig.go, Tier 2): a user's bearer token, or a
//     complete client-certificate-data/client-key-data pair, moves into
//     the vault, replaced with an exec block invoking `jit
//     k8s-exec-credential` (client-go's exec plugin protocol). Backed up.
//   - Terraform Cloud (terraform.go, Tier 2): each host's API token in
//     ~/.terraform.d/credentials.tfrc.json moves into the vault, replaced
//     by Terraform's own credentials-helper protocol — a
//     credentials_helper block in ~/.terraformrc plus a
//     terraform-credentials-jit wrapper script invoking `jit
//     terraform-credentials` (get/store/forget, so `terraform
//     login`/`logout` keep working through the vault afterward). Fails
//     loud before mutating anything if a different helper is already
//     configured — Terraform allows exactly one. Both files backed up.
//   - npmrc (npmrc.go, Tier 4): global ~/.npmrc always checked, plus
//     project .npmrc under the chosen root. Architecturally different
//     from the other five — npm has no native credential hook, and an
//     npmrc file mixes secrets with ordinary settings that must survive
//     untouched, so this uses a template-based mount
//     (mount.FormatTemplate/mount.Entry.TemplatePath) rather than
//     regenerating the whole file from the vault. Backed up first, and
//     gets the same .pointers companion .env does.
//
// archived.go's LooksArchived/FilterArchived is jit migrate home's only
// safety net over its wider discovery (GAPS.md #26): a live-mounted pipe
// in a project nobody revisits is worse than leaving it plaintext, since
// nothing will ever serve it again. jit migrate local never applies
// this — an explicit cd into an old project isn't an implicit sweep.
//
// Shell-config, MCP, AWS, kubeconfig, and Terraform profiles all live in a
// home-rooted global store (profile.GlobalRoot), not the project-relative
// .jit/profiles/ .env migration uses — none of them can be relied on to
// resolve from a particular project directory (a new shell, an MCP host's
// subprocess, the AWS CLI, or kubectl can all invoke from anywhere), so
// profile.Load falls back to the global store when a project-relative
// lookup misses. npmrc uses the global store only for the global
// ~/.npmrc; a project-local .npmrc uses the project-relative store like
// .env does, since it genuinely is tied to that project — rooted at that
// file's own directory, not necessarily the invoking cwd. jit migrate
// home discovers .env/project-npmrc files under completely unrelated
// projects, so internal/cli/migrate.go passes each file's own directory
// as its profilesRoot there, not cwd — passing cwd would have derived a
// profile name/location disconnected from the project the secret
// actually came from (a real bug caught while building GAPS.md #26, via
// tracing deriveProfileName's own relative-path logic, not a failing
// test). jit migrate local is unaffected: every file it discovers
// genuinely is under cwd already.
//
// GCP application-default-credentials are detected by audit but have no
// migration path yet — see GAPS.md #16.
//
// revealhook.go's InstallRevealHook is a small addition on top of the .env/npmrc
// live-mount path (GAPS.md #2): after creating a mount, migrate best-effort
// wires an automatic `jit agent reveal` call into whatever project-level
// pre-run hook already exists (an existing .envrc, or package.json's
// dev/start scripts) — the automated half of the decoy-by-default gate's
// trust signal, on top of internal/cli/agent.go's automatic post-unlock
// reveal window and the fully manual `jit agent reveal` command.
package migrate
