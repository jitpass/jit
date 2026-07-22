# Spike Findings: PATH shims for a `jit wrap <cli>` feature

**Question:** for a 1Password-Shell-Plugins-style feature ("keep typing `gh`, the token materializes only inside that one process"), which wrapping mechanism should jit use — shell aliases (1Password's approach) or PATH shims (asdf/mise's approach)? Specifically: (1) do aliases actually cover the invocation paths developers hit daily (scripts, Makefiles, tools spawning tools)? (2) can a shim named after the tool, sitting first in PATH, reliably find the *real* binary without infinite recursion? (3) what latency does shim + `jit run` add per invocation with an unlocked agent?

**Environment:** macOS 26.5.0 (Darwin 25.5.0, arm64), Go 1.26.4, jit built from source at `~/go/bin/jit`, agent running and unlocked. The wrapped CLI is a stand-in script (`realbin/fakecli`) that reports whether `FAKE_TOKEN` arrived (length only, never the value); the secret is a throwaway (`spike-wrap/FAKE_TOKEN`, removed after).

## Result 1: aliases silently fail exactly where secrets are needed; shims cover everything

With `alias fakecli=<wrapped>` set in the parent shell:

| Invocation path | Alias | Shim |
| --- | --- | --- |
| Typed in the defining shell | injected | injected |
| A script calling `fakecli` (build script, git hook, Makefile) | **missing — silent** | injected |
| execvp spawn, no shell (`env fakecli`, i.e. git→gh style) | **missing — silent** | injected |

The alias failures are the bad kind: the CLI still runs, just without its credential, producing confusing auth errors far from the cause. This is a real gap in 1Password's own approach (documented in their FAQ as "plugins don't work in scripts"). **Conclusion: build `jit wrap` on PATH shims, not aliases.**

## Result 2: recursion is fully controllable

The shim (one Go binary, copied into a shim dir under each wrapped tool's name) finds the real binary by walking PATH and skipping any entry that resolves (via `EvalSymlinks`) to its own directory. Verified:

- Real binary present further down PATH → found and exec'd, args and exit code (`42`) propagate intact through shim + `jit run` (which `execve`s, so nothing extra stays in memory).
- Real binary absent → clean `exit 127` with a named error, no loop.
- Shim dir appearing twice in PATH via a symlink → skip still holds, injection works.
- PATH skip artificially defeated → a `JIT_SHIM_GUARD_<TOOL>` env guard catches the second pass and aborts (`exit 127`) instead of forking forever.

## Result 3: overhead is ~17 ms per invocation — imperceptible for interactive CLI use

30 timed invocations each, warm agent, warm caches:

| Pipeline | ms/invocation |
| --- | --- |
| real `fakecli` direct (baseline) | 8.9 |
| shim → stub injector (shim cost alone) | 33.0¹ |
| `jit run --profile … --` direct, no shim | 24.4 |
| **full: shim → `jit run` → agent decrypt → tool** | **26.3** |

¹ The stub is a `/bin/sh` script, so this row pays an extra shell spawn; the honest comparison is baseline (8.9) vs full (26.3): **~17 ms added**, of which most is `jit run`'s vault/agent round-trip, already accepted elsewhere in jit. Fine for human-driven CLIs (`gh`, `stripe`, `terraform`); worth flagging for anything invoked hundreds of times in a tight loop.

Not measured: the locked-agent path (first use of a session triggers the Touch ID prompt with jit's "what asked and why" attribution — same flow `jit run` already has; nothing shim-specific to learn there, and measuring it requires an interactive approval).

## Implication: `jit wrap <cli>` is buildable now, mostly from existing pieces

The spike validates the risky third of the feature. The full shape:

1. **Catalog** (`internal/wrap/catalog.go`): per-CLI entries — env var(s) the tool reads (`gh` → `GH_TOKEN`), where its plaintext credential lives today (`~/.config/gh/hosts.yml`), how to extract it. This is data entry, not risk; 1Password's public plugin list is the coverage roadmap.
2. **`jit wrap gh`**: find the existing plaintext token (reusing audit's detection), `vault set` it, write a `wrap-gh` profile (global scope, like shell/MCP migrations), install the shim (`~/.jit/shims/gh`), verify PATH order, offer to scrub the original file (backed up encrypted first, like every migrate).
3. **Shim binary**: this spike's `main.go`, hardened — becomes either a tiny separate binary or `jit shim-exec` invoked via argv[0] dispatch.
4. **`jit scan`** learns to report wrappable plaintext tokens ("gh token in hosts.yml — `jit wrap gh` fixes this"), which is how developers discover the feature.

Open questions for the real implementation, none spike-shaped: tools that *require* a config file rather than an env var (kubectl-style exec plugins or live-mounts cover those), `jit migrate undo` integration, and whether `wrap` is a migrate subcommand or a top-level verb.

## Cleanup

`spike-wrap/FAKE_TOKEN` removed from the vault; built shim binaries, the generated `failcli` fixtures, and `/tmp` scratch files deleted. What remains in this directory is source only (the profile manifest holds a vault path, no value).

## How to reproduce

```bash
cd spike/cli-shim-wrap
go build -o shimbin/fakecli .
jit vault set spike-wrap/FAKE_TOKEN "spike-fake-token-1234567890"
export PATH="$PWD/shimbin:$PWD/realbin:$PATH"

fakecli hello world        # → "FAKE_TOKEN present (27 chars)" via real jit run
sh -c 'fakecli in-script'  # shims cover scripts; aliases don't
env fakecli via-execvp     # ...and execvp spawns

jit vault rm spike-wrap/FAKE_TOKEN && rm -rf shimbin
```
