# AI Jobs: an AI tool runs your script, and never holds the key

**Status: steps 1 (engine), 2 (jobs that never ask) and 3 (`jit mcp`) built
2026-09-25 on branch `ai-jobs`, not yet merged or released.** Step 4 (the
app) is not built. App mockup:
`jit-app/docs/design/mockups/Jobs.html` (published as an artifact for
review). Read `standing-grants.md` first; the job key below is its grant
key, reused.

The ask, in the user's words: *Claude Desktop can't work with jit — is
there a secure way to give jit to the Claude Desktop sandbox?* It grew,
over one conversation, into a narrower and more useful question: how does
any AI tool run a script that needs a secret **without the model ever being
able to read that secret**.

    jit job allow notion-guests --profile notion -- .venv/bin/python list_guest_users.py
    jit job run notion-guests            # from any terminal agent
    jit mcp                              # the same jobs, for a sandboxed app

## The facts this rests on (checked 2026-09-25)

1. **Cowork's shell is a Linux VM, and jit is macOS-only by decision.**
   The VM is `com.apple.Virtualization.VirtualMachine` (pid 53916 at the
   time), parented by `launchd`, not by Claude.app
   (`~/Library/Logs/Claude/cowork_vm_swift.log`, `ps`). `jit run` cannot
   execute inside it.
2. **From the host, the whole VM is one process.** Every program inside it
   — the user's script, Claude's `bash`, `cat .env` — reaches the host as
   that one process. Nothing jit can see tells them apart, so no grant,
   consent or lineage rule can admit one and refuse another. A grant "to
   the VM" is a grant to the model's shell.
3. **Claude Desktop bridges local stdio MCP servers into Cowork.** The
   servers run on macOS, started by the app from
   `claude_desktop_config.json`'s `mcpServers`, and the log shows the
   bridge announcing them to the VM (`[localMcpBridge] … (+0 local-mcp)`
   with none configured). This is the one door from the VM to a host
   process the user chose.
4. **Terminal agents already reach jit.** Claude Code in iTerm2 runs
   `jit status` and gets the service (checked from such a session). A
   sandboxed one needs the socket allowed, which
   `docs/service/sandboxed-callers.md` already covers.
5. **But a terminal agent chooses the command.** `jit run --profile notion
   -- env` is as easy to type as the real script. The Touch ID prompt names
   the caller, not what the command will do with the key; a standing grant
   removes even that prompt. Today jit keeps a secret off disk and out of
   other processes. It does not keep it from the agent that asked.
6. **The folders Cowork opens are writable by the model**, including the
   script, its `.venv`, and `.jit/profiles/*.yaml`
   (`localAgentModeTrustedFolders` holds `~/Security-Ops/custom_scripts`).
   So a rule stored there, a script path, or a profile name alone is
   something the model can change after you approve it.
7. **Fingerprinting a job folder is cheap.** The notion folder is 236
   regular files, 3 symlinks, 3.8 MB of `.venv`; hashing all of it takes
   0.28 s. Python writes `__pycache__` into that tree on every run (10
   such directories there now), so a naive fingerprint breaks on its own.

## The decision: the service runs the job

A **job** is a command you approved, with the secrets it gets. When an AI
tool asks for a job, it is the **jit service** that decrypts, starts the
command, reads its output, hides the secret values in it, and hands back
the result. The caller sends a name and gets text. It never holds a key,
so there is nothing in its process, its sandbox or its transcript to leak.

```
AI tool ── "run notion-guests" ──▶ jit service
                                     ├─ fingerprint unchanged?   no → refuse, name the file
                                     ├─ ask mode: Touch ID, or the job's own key
                                     ├─ spawn: fixed argv, fixed folder, env = the approved secrets
                                     ├─ read stdout/stderr, hide every value it injected
◀── exit code + output (values hidden) ┘
```

Two ways in, one engine:

| Caller | Transport | Why |
|---|---|---|
| Terminal agent (Claude Code, Codex, Gemini CLI) | `jit job run <name>` | It already reaches the socket (fact 4) |
| Sandboxed app (Cowork) | `jit mcp`, stdio, started by the app | The only door from the VM (fact 3) |
| Cloud agent | None | It cannot reach this Mac; give it its own narrow token |

### Why not a grant

The first draft scoped `jit mcp` with a standing grant
(`--process jit-mcp --profile notion`). With the service running the job,
that grant has nothing to do: no caller ever unwraps, so there is no
caller for a grant to narrow. It was also weaker than it looked: a grant
matches a program *name* under an app, and every `jit` under that app
shares the name, including a raw `jit run` the agent types itself. The
job's own key (below) replaces it, and is tied to the job, not to who
called it.

Grants stay what they are: for a program that must hold a secret itself
(an MCP server that reads its key at startup, a long-running tool). Jobs
are for the other case, a script whose *output* is what the agent wanted.

### Why the caller does not decide

Consistent with `internal/agent/doc.go`: caller identity explains and
audits, it never decides. A job runs for any same-user caller that asks,
because what it hands back is the output you approved when you approved
the job, with the values hidden. The caller is named in the prompt (when
the job asks) and in `jit audit`, never used as a gate.

## What a job is

`(name, folder, argv, secrets, fingerprint, ask, outputs)`.

- **Name** — `[a-z0-9-]`, unique, what the agent asks for.
- **Folder** — the absolute working directory, resolved at approval.
- **argv** — exact, resolved at approval. The executable is recorded as
  its resolved path (`.venv/bin/python` → the uv cpython it links to). No
  shell. No arguments from the caller in v1.
- **Secrets** — the concrete vault paths the profile resolved to at
  approval, with each value's `device_wrapped_sha256`, exactly as a
  standing grant stores them. A later edit to `notion.yaml` (fact 6)
  never changes what the job injects; it shows up as a changed file.
- **Fingerprint** — see below.
- **Ask** — `each-time` (Touch ID per run, naming the caller) or `never`
  (the job's own key, no prompt, until you change it or remove the job).
- **Outputs** — folders the job may write to, reported back to the caller
  as new or changed files. Default: none. Nothing is copied or read from
  them; the caller gets paths.
- **Shown** — secrets the user marked as safe to appear in output (below).

### Storage

`~/Library/Application Support/jitpass/jobs.json`, mode 0600, atomic,
versioned the way `grants.json` is (a newer version is refused and never
written over). That directory is the one `sandboxed-callers.md` already
says never to give a sandbox write access to; the job list lives there for
the same reason. It is never inside a project, so nothing in a folder an
agent can write defines what a job is (fact 6).

A `never` job's key is a grant key: 32 random bytes in the keychain as
`com.jitpass.grant.key` / `job:<name>`, the DEKs re-wrapped under it at
approval, reusing `standing.go`'s ledger, seal and rotation handling. An
`each-time` job has no key; it unwraps through the session like `jit run`.

## Approving a job

A job exists only after a disclosed Touch ID, from one of three places.

1. **Terminal.** `jit job allow <name> [--profile p] [--ask never]
   [--output <dir>] [--show VAR] -- <cmd…>`, run in the folder. It prints
   the whole job (command, folder, secret names, file count, ask mode),
   then the Touch ID says it again:
   *"Let AI tools run notion-guests (list_guest_users.py in notion) with 3
   secrets. They see what it prints, never the values."*
2. **The app.** The Jobs window's New Job… sheet, drawn in the mockup.
3. **An agent asks.** `jit job request` / the MCP `request_job` tool sends
   a proposed job. Nothing is created. JitPass shows a notification and
   opens the same sheet, pre-filled, with a banner naming who asked. The
   user reads the command and approves or dismisses. An agent can
   propose; only the user can approve. A proposed job always opens at
   `each-time`, whatever the agent asked for, and its `why` is shown as
   the agent's words, unchecked. Without the app running, the
   request is refused with the `jit job allow` line to type.

Approval refuses, with a sentence, a command that would hand the values
straight back: an interpreter with an inline program (`python -c`,
`node -e`, `sh -c`, `bash -c`, `osascript -e`), or `env`/`printenv`/
`cat`/`echo` as the executable. That list is a speed bump for honest
mistakes, not a boundary; the boundary is the human reading the command.

## Running a job

`job_run{name}` over the socket; a new agent op beside `OpGrantCreate`.

1. Load the job. Refuse if missing.
2. **Fingerprint.** Recompute; refuse on any difference, naming the first
   changed paths: *"list_guest_users.py changed since you approved it."*
   The job goes to the **Changed** state until re-approved.
3. **Secrets.** `each-time`: disclosed Touch ID naming the caller and the
   job. `never`: open the DEKs with the job key. A rotated secret (hash
   mismatch) refuses the run and marks the job, as standing grants do.
4. **Mounts.** The same swap `jit run` does (`mount.SwapToPointer`) for the
   folder's mounts, for the run's lifetime. The notion script calls
   `load_dotenv(".env")`; the pointer file keeps that harmless.
5. **Spawn** as a child of the service: argv as approved, the folder as
   cwd, an environment built from scratch — the approved secrets, `PATH`
   and `HOME` captured at approval, `LANG`, and nothing from the caller.
   No stdin. Python-specific: `PYTHONPYCACHEPREFIX` points at a
   jit-owned cache per job, so a run never writes into the fingerprinted
   tree (fact 7).
6. **Read output** through the masker (below) into a capped buffer: 256 KB
   total, keeping the tail on overflow and saying so; 10 min timeout, then
   SIGTERM, then SIGKILL after 5 s.
7. **Return** exit code, duration, masked stdout and stderr, and the new or
   changed files under the job's outputs.
8. **Audit** one record: job, caller (pid, ancestry, the app it ran
   under), ask mode, exit code, bytes hidden per secret. `jit audit` and
   the Jobs window read it.

### Fingerprint

At approval and at every run, over the job folder:

- Every regular file, its relative path and SHA-256. Every symlink, its
  target string. FIFOs, sockets and the job's own outputs are skipped.
- The resolved executable's SHA-256, even when it lives outside the folder.
- Skipped by name: `.git/`, `__pycache__/`, `node_modules/.cache/`. The
  first holds nothing the job runs; the other two are rewritten by the
  runtime, and step 5 keeps Python from reading or writing them in the
  tree at all.
- A folder over 20,000 files or 500 MB is refused at approval with a
  sentence: fingerprint a narrower folder. The limit is a guess to confirm
  once more folders are measured; the one measured is 236 files, 0.28 s.

Stored as one root hash plus the per-file list, so a refusal can name
what changed. jit stores hashes, not copies, so it can say *which* file
changed but not show the old text. The mockup's "Show Changes…" opens the
file in the user's editor, and when the folder is a git repo, runs
`git diff` against the commit recorded at approval.

### Hiding values in the output

The service knows exactly which values it injected, so it replaces each one
before a byte reaches the caller:

- Every injected value of 8 characters or more, and its standard and
  URL-safe base64, hex, and URL-encoded forms, becomes `[hidden: NAME]`.
- Values the user marked **shown** at approval pass through. The notion
  job is the reason this exists: it prints every user's email, and
  `INTERNAL_DOMAINS` is `blockaid.co`. Hidden, every line would read
  `x@[hidden: INTERNAL_DOMAINS]`. The sheet lists each secret with a
  Hidden / Shown switch, Hidden by default.
- A match across a read boundary is caught by holding back
  `len(longest form) − 1` bytes between reads.
- The count per secret goes into the audit record, and the Jobs window
  says *"hid NOTION_API_KEY twice in the last run"*, because a script that
  prints its key is a bug worth knowing about.

What this cannot catch, stated plainly: a value split across two prints,
reversed, encrypted, or sent over the network by the script itself.
Hiding stops the accident. The fingerprint and the human read of the
command are what stop the deliberate case.

## `jit mcp`

A stdio MCP server, hand-rolled over `encoding/json` (JSON-RPC 2.0,
`initialize`, `tools/list`, `tools/call`). No SDK: the protocol surface is
three tools, and the dependency rule in `TECH_STACK.md` §2 is a threat-model
check, not taste, which matters more than usual for the one process a model
talks to.

| Tool | Does |
|---|---|
| `list_jobs` | Names, one-line description, ask mode, state (Ready, Changed, Rotated). Never argv secrets or values |
| `run_job` | `{name}` → exit code, output with values hidden, new files |
| `request_job` | `{name, folder, argv, profile, why}` → "sent to JitPass for approval"; creates nothing |

It is a thin client of the socket: every decision above happens in the
service, so the terminal and the MCP paths cannot drift.

`jit mcp install --client claude-desktop` adds the entry to
`claude_desktop_config.json` after writing a backup beside it, and prints
the one change it made. `--client cursor` and others follow once each is
checked to start stdio servers on the host rather than in its sandbox;
until then they are documented, not automated.

## Where it is built

All of it in **jitpass/jit**, shipped in the one `jit` binary. The app
gets no socket code and no new decisions, per jit-app's rules: it renders
jobs and sends the same ops the CLI sends.

| Piece | Where | Holds |
|---|---|---|
| Job store, fingerprint, masker | `internal/job` (new) | `jobs.json` load/save, the folder hash, the output filter. Pure Go, no CGo, testable without the service |
| Runner | `internal/agent` (`job.go`, new) | The `job_allow`, `job_list`, `job_remove`, `job_run`, `job_request` ops: unwrap, spawn, read, audit. The only code that puts a secret into a child's environment |
| MCP server | `internal/mcp` (new) | JSON-RPC 2.0 over stdin/stdout, three tools, and nothing else. A socket client: it never unwraps, so it holds no secret to lose |
| Commands | `internal/cli/job.go`, `internal/cli/mcp.go` | `jit job allow/list/remove/run/request`, `jit mcp`, `jit mcp install` |
| App | jitpass/jit-app | The AI Jobs window and sheets, mirroring the new ops in `JitAgentClient/Protocol.swift` |

`jit mcp install --client claude-desktop` writes the command as
`/opt/homebrew/bin/jit`, the cask's symlink (today it resolves to
`/Applications/JitPass.app/Contents/MacOS/jit`), never the bundle path
itself, so an app update that moves the binary does not break the entry.
The `mcp` package gets the same `doc.go` treatment as every `internal/`
package: what it trusts (nothing the model sends except a job name and a
proposal) and what it never does (unwrap, write files, run a command).

### Where it shows in the app

Drawn in the mockup, frames J–M. Each is an existing surface with one
addition, and each action is a CLI command the app runs, per jit-app's
rule that the app is never the only way to do something.

- **Panel** — an `AI Jobs` row under Grants: `1 needs you` (amber) when a
  job changed or a proposal waits, `3 ready` otherwise. Shown once any job
  exists or an app is connected.
- **AI Agents** — a `Can run` row under `Can reach` on every agent card,
  linking to AI Jobs. A stopped job is a header to-do. **Claude Desktop
  gets a card** when `/Applications/Claude.app` exists, with only the rows
  jit has facts for (Can run, This week, Asks through). Before it is
  connected, the card's one action is Connect (`jit mcp install`).
- **Tools** — an `AI Jobs…` item in the ··· menu and nothing else. A tool
  holds its secrets itself (Tier 1); listing jobs there would mix the two
  models.
- **Onboarding** — one switch on the last step, only when Claude Desktop is
  installed, **off** by default because it edits another app's settings.
  It creates no jobs.

## What this does not protect

- **A script written to leak.** One you approved that posts its key to a
  server, or prints it encoded in a way the masker does not know. The
  fingerprint makes sure it is the script you read; it cannot make the
  script honest.
- **Files the job writes.** Outputs are reported by path, not scanned. The
  notion CSV holds emails, not keys; a job that writes a key to a file is
  the previous bullet.
- **Anything the job itself is allowed to do** with the API. A read-only
  Notion token limits that; jit does not.

## Build order

Each step ships alone, and each test runs against the pre-change code to
prove it fails there.

1. **Engine (jit).** `jobs.json`, `jit job allow/list/remove/run`, the
   fingerprint, the spawn with a scratch environment, the masker, the
   audit record. Tests: a changed script is refused and names the file; a
   `notion.yaml` remap is refused as a change and injects nothing; the
   masker hides a value split across two reads and its base64 form; a
   shown value passes; `python -c` is refused at approval; a run does not
   change the fingerprint (the `__pycache__` case); the child's
   environment holds nothing from the caller.
2. **`never` jobs.** The job key on the standing-grant ledger. Tests:
   runs with the vault locked and no prompt; removing the job deletes the
   key and the next run is refused; a rotated secret refuses and marks.
3. **`jit mcp`.** The server and `install`. Tests: a golden JSON-RPC
   exchange for each tool; `run_job` over the pipe returns hidden output;
   an end-to-end run from Cowork on the notion job, by hand, recorded here.
4. **App (jit-app), and one engine change it needs.** The AI Jobs window,
   New AI Job sheet, request banner, Changed and Rotated states, the job
   run sheet (below), and the wiring in the panel, AI Agents, Tools and
   onboarding, per the mockup and nothing more.

   **One sentence, not two (decided 2026-09-25).** With the app running, a
   prompt is read twice: the app's sheet shows the whole request, then the
   Touch ID dialog repeats it. The dialog cannot simply go: it is the one
   of the two that is always there (no app, app quit, terminal-only Mac),
   the one Touch ID actually approves, the one no other program can draw,
   and its sentence is what the audit records. So it stays self-contained,
   but shortens when a sheet came first:

   - In `promptOrBroker`, when the broker answered allow, the dialog's
     reason becomes a short confirmation that still names what runs and who
     asked: "confirm: run notion/list_guest_users.py for Claude". Any
     same-user process can subscribe as a broker, so the short form must
     never drop those facts: a process posing as the app then gains nothing,
     because the dialog still says what the fingerprint approves.
   - With no broker, or a broker that did not answer, the full sentence as
     today.
   - The audit event keeps the FULL sentence either way (the event's Cause
     is set before the prompt), so the trail never records the short form.
   - It applies to every disclosed prompt the app brokers, grants and
     consent included, not only jobs: each gets its own short form, built
     from the same resolved facts as its long one, and a test holds each
     short form to the facts its long form names.

   **The job run sheet.** The app's generic consent sheet says "remembered
   until the vault locks", which is false for a job: an each-time job asks
   on every run. A pending event whose op is `job_run` gets its own sheet:
   which job, the command, the folder, who asked (the launcher, e.g.
   Claude), how many secrets, and "asks again next time".

## Decided while building step 1

Where the build settled something this page left open, or found a case it
did not name:

- **Short values.** A hidden value is hidden as typed from 4 characters
  (`job.MinHiddenRaw`) and in every encoding from 8 (`job.MinHidden`).
  Under 4 it is not hidden, because hiding "443" hides half the output, and
  the run says so in its notes instead of pretending.
- **Executable resolution.** `job.ResolveExe` resolves like the approving
  shell (relative to the folder when the name has a slash, else on the
  captured `PATH`, never a relative `PATH` entry) and does NOT resolve
  symlinks: a venv's `bin/python` finds its venv from the path it was
  started as. The fingerprint hashes the symlink's target separately.
- **Approving again** is `jit job allow NAME --replace -- …`. `jit job list`
  prints that exact line for a stopped job.
- **The folder's only profile** is used when `--profile` is omitted; two or
  more is an error naming them.
- **`never` jobs** (step 2, `--ask never`). The approval mints a key named
  `j-<random hex>` in the standing-grant key store (keychain service
  `com.jitpass.grant.key`), seals each secret's DEK under it with the class
  as AAD, and keeps the sealed copies in `jobs.json` (`key_wrapped`, `wrap:
  aead-v1`). Never the job's name as the key's name: a key that outlives its
  record after a crash can then never be mistaken for a later job's. Every
  failure after the key exists deletes it; removing the job deletes it;
  approving again mints a new one and deletes the old, including when the
  job goes back to each-time. A missing or unopenable key **refuses** the
  run and does not fall back to a prompt: a job set to run while the human is
  away would otherwise sit on a dialog nobody answers. The one-time prompt
  reads "let AI tools run notion-guests (3 secrets) unasked, until removed;
  never the values". The orphan-key reconciler standing grants still lack
  must know `j-` ids too.
- **The job's environment** is PATH and HOME from approval, USER, LOGNAME,
  LANG, TMPDIR, `PYTHONPYCACHEPREFIX` (a jit-owned cache per job) and
  `JIT_JOB`, plus the secrets. Nothing from the service or the caller, and a
  test proves a service variable does not leak.
- **The whole run is one process group**, so the time limit ends the
  script's children too.
- **Prompts.** "jit is trying to let AI tools run notion-guests (3 secrets);
  they see output, never the values." and, per run, "…run notion-guests (3
  secrets) for Claude; it sees output, never the values." A test holds both
  under the 90-rune dialog limit with the promise intact at the worst case.

### After the second review (2026-09-25)

A review of steps 1 and 2 found ten gaps; each fix has a test that fails
without it.

- **The folder is resolved through symlinks** at approval, and an empty
  fingerprint is refused. A job approved through a symlinked path
  (`/tmp` → `/private/tmp`, a linked project) used to fingerprint as empty,
  so no edit could stop it. Output folders are resolved the same way, as far
  as they exist, or every declared output would have stopped the job.
- **`__pycache__` is fingerprinted.** It was skipped on the grounds that the
  runner redirects bytecode, but `python -I` and a child with a cleaned
  environment ignore `PYTHONPYCACHEPREFIX` and load a planted `.pyc` whose
  header matches its source. A jit run never writes there, so the entry is
  stable.
- **Each run gets a fresh, empty bytecode cache**, removed afterwards. A
  per-job cache that persisted was a place to leave poisoned bytecode.
- **Symlinks out of the folder**: one to a file is fingerprinted by the
  content it points at; one to a folder is refused, as is an interpreter
  pointed at a folder outside (`python ../tool`). Files are hashed only when
  they are regular files once opened, without blocking, so a path swapped
  for a named pipe fails fast instead of hanging every list and run.
- **A stop is sticky.** A detected change, rotation or missing key stops
  the job until it is approved again; putting the file back does not
  reopen it. Without this a caller could retry a swap for free until one
  landed between the check and the start.
- **The folder is checked again after the run.** A change during the run
  withholds the output, which may have been shaped by the changed code, and
  stops the job. A job that writes into its own folder stops the same way,
  and the message says to declare that folder with `--output`.
- **The approval prompt names what the service resolved, never the job's
  name**: "jit is trying to let AI run notion/list_guest_users.py with 3
  notion secrets, 1 shown, unasked till removed". Any process that reaches
  the socket can ask for an approval and chooses the name, so a familiar
  name on a request that runs something else is the prompt this must not
  show. The shown count is there because "never the values" is false for a
  value marked shown.
- **The masker also hides** base64 of a value embedded at either of the
  other two alignments (`Basic base64("user:" + token)`), the JSON-escaped
  form (a key with quotes, or a multi-line key in a JSON log), and each line
  of a multi-line value from 16 characters (a PEM body).
- **The run environment switches off** `~/.zshenv` (`ZDOTDIR` empty) and
  user site-packages (`PYTHONNOUSERSITE=1`).

What stays trusted, stated rather than hidden:

- **Programs the job calls** from the captured `PATH` (`git`, `curl`, a
  Homebrew tool) and their own configuration. The fingerprint covers the
  folder, the files the command names, and the program it starts.
- **Code a Python venv loads through an editable install** (`.pth` pointing
  outside): the `.pth` file is fingerprinted, the code it points at is not.
- **A process that reaches the socket can ask for approval.** The Touch ID
  prompt is the boundary, which is why it names resolved facts. Step 4's
  sheet shows the whole command before the prompt.
- **A narrow race remains** between the last check and the moment the
  interpreter reads a file it imports late. The sticky stop and the check
  after the run make every losing attempt stop the job for good.

### After the Cowork test (2026-09-25)

Run end to end from Claude Desktop's Cowork with a dev build: Claude listed
the job, called run_job, the human approved Touch ID, and the Notion script
ran with its real key; Claude saw the summary and never the key. Three
things it showed were wrong:

- **Every run raised "decoy served".** The folder's `.env` mount handed the
  job's `load_dotenv` the decoy and reported it like any stranger's read.
  Now a reader gets the inert pointer file `jit run` swaps in, and no serve
  is recorded, when every holder of the mount descends from the service
  (every job is its child, so there is no pid to register and no race) and
  the mount is inside the folder of a job running now. A job reading ANOTHER
  project's `.env` still gets the decoy and still raises the alert.
  (This replaces the known gap this page used to list.)
- **The prompt said "for jit-dev" and the app "launched by disclaimer".**
  Claude Desktop starts MCP servers through `Contents/Helpers/disclaimer`,
  now a relay like a shell, so the launcher is Claude; and jit is recognised
  by its executable, not its name, so a renamed build is still jit.
- **The app's sheet says "remembered until the vault locks"**, which is
  false for a job. That is the app's generic consent wording; step 4 gives
  job runs their own sheet.

## Open decisions

1. **The name.** Decided 2026-09-25: **AI Jobs** in the app (window,
   sheet, panel row). The CLI stays `jit job`: a command is typed, not
   read, and jit's other commands are single nouns.
2. **Default ask mode.** `each-time` is safer; `never` is what makes
   Cowork useful while you are away. Recommendation: `each-time` by
   default, `never` one click away on the sheet, with the Grants sheet's
   "until you remove it" wording.
3. **Arguments.** v1 takes none; a date range or a user id would each need
   a new job. A later version could allow typed parameters declared at
   approval (an enum, a date, `[a-z0-9-]+`), never free text.
   Recommendation: none in v1, and see what the first jobs ask for.
4. **Where it lives in the app.** Its own window, reachable from the
   panel and the AI Agents window's menu, with a line on each agent card
   ("Can run 2 jobs"). Recommendation: as drawn.
