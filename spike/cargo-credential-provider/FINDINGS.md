# Cargo credential-provider spike — findings

2026-09-06, cargo 1.98.0 (Homebrew), macOS. Method: a local HTTP server
plays a minimal sparse registry (`config.json` with `auth-required` +
the owners API endpoint) and records every Authorization header; cargo
runs against it with a scratch `CARGO_HOME`. `go run .` reproduces
everything below.

## Verdict

**Tier 2 holds up.** `jit migrate ~/.cargo/credentials.toml` can be a
native credential hook like AWS's `credential_process` and Terraform's
`credentials_helper`, with `cargo login`/`logout` kept working through
the vault. Implement the full JSON protocol (a `cargo-credential-jit`
wrapper exec'ing `jit cargo-credential`), NOT `cargo:token-from-stdout`
— the stdout form is get-only and fails `cargo login` with
"requested operation not supported".

## What was verified empirically

1. **`cargo:token-from-stdout <cmd>` works for reads.** The command runs
   once per cargo invocation; its stdout is sent verbatim as the
   `Authorization` header on API operations (`cargo owner --list`), and
   on index fetches when the registry declares `auth-required`.

2. **Precedence: LATER entries in `global-credential-providers` win.**
   With `["cargo:token", "cargo:token-from-stdout …"]` and a token
   present in credentials.toml, the provider's token was sent, not the
   file's. So jit's provider appended last shadows any stale plaintext
   token — and a post-migration `cargo login` cannot silently write a
   new plaintext token that takes effect behind jit's back.

3. **The JSON protocol is simple and the shapes below are accepted**
   (cargo spawns the provider per operation with argv
   `[path, "--cargo-plugin"]`, JSON lines over stdin/stdout):

   - greeting, provider → cargo: `{"v":[1]}`
   - get, cargo → provider:
     `{"v":1,"registry":{"index-url":"…","name":"testreg"},"kind":"get","operation":"read"}`
   - get response:
     `{"Ok":{"kind":"get","token":"…","cache":"session","operation_independent":true}}`
   - login, cargo → provider: same envelope with `"kind":"login"`,
     `"token":"…"` (and a `login-url` when the registry advertises one);
     response `{"Ok":{"kind":"login"}}`. **`cargo login` exits 0.**
   - logout: `"kind":"logout"` / `{"Ok":{"kind":"logout"}}`. Exits 0.

4. **Registry selection is provided, both ways.** token-from-stdout gets
   `CARGO_REGISTRY_NAME_OPT` + `CARGO_REGISTRY_INDEX_URL` in the
   environment; the JSON protocol carries `registry.index-url` and
   `registry.name` in every request. Multi-registry vault lookup keys on
   the index URL (stable), with the name as display.

5. **Fallthrough works.** cargo:token configured first with no token for
   the target registry falls through to the next provider cleanly.

6. **`{"Err":{"kind":"not-found"}}` on get is accepted and falls back.**
   With `["cargo:token", <jit>]` configured and jit answering not-found,
   cargo used the credentials.toml token; with only jit configured it
   failed clean ("no token found for `testreg` … log in using this
   registry's credential provider"). So jit answers not-found for any
   registry it holds nothing for, costs no prompt, and never blocks an
   unmigrated registry.

7. **`{"Err":{"kind":"other","message":"…"}}` surfaces the message.**
   cargo prints it as the last `Caused by:` in its error chain — so a
   locked/denied vault for a registry jit DOES hold reports itself in
   jit's own words instead of decaying into "no token found".

## Implementation notes for the real thing

- Provider strings are whitespace-split, so the config must reference a
  space-free path: a wrapper script exec'ing `jit cargo-credential`, the
  same shape as `terraform-credentials-jit`.
- `cache":"session"` keeps cargo from re-invoking the provider within
  one invocation; each new cargo process asks again — exactly jit's
  just-in-time model.
- The provider is spawned fresh per operation (three argv lines in the
  transcript for get/login/logout runs). No daemon assumptions.
- `credentials.toml` is INI-shaped TOML (`[registry]` /
  `[registries.<name>]`, one quoted `token = "…"` per table) — audit's
  parseINISections already reads it (scanCargoCredentialFile).
