---
title: AI jobs
description: Let an AI tool run a script that needs a secret without ever seeing the secret - approve the command once, connect Claude Desktop or Cursor, and the tool gets the output with every value hidden.
---

# AI jobs - let an AI tool run your script, never your key

An AI job is a command you approve once, with the secrets it needs. An AI
tool runs it by name. The jit service runs it on your Mac and hands the tool
the output, with every secret value replaced by `[hidden: NAME]`. The tool
never holds a key, so nothing in its process, its sandbox or its
conversation can leak one.

It is for the moment an AI tool asks to run something like
`export_pages.py`, which needs a Notion API key, and you want the result
without giving the tool the key.

## 1. Approve a job

**In JitPass:** open **AI Jobs** from the menu bar (or from AI Agents or
Tools) and press **New AI Job…**. Pick the profile whose secrets the script
needs: its folder is where the job runs, unless you choose a folder inside it
where the script is. Then pick the script from the ones in that folder
(Python runs from the folder's `.venv` when it has one), or type another
command. Press **Approve with Touch ID**.

**In a terminal**, from the job's folder:

```sh
cd ~/code/scripts/notion
jit job allow notion-export -- .venv/bin/python export_pages.py
```

Either way you see the whole job first: the command, the folder, each
secret, and whether it asks each time. Then one Touch ID. Add `--dry-run` to
see all of that without approving anything.

Every value is hidden in the output unless you mark it shown. Mark a value
shown only when it is configuration the script prints, never a key: the
notion script prints the workspace name in every line, so its
`NOTION_WORKSPACE` is shown (`--show NOTION_WORKSPACE`).

## 2. Let your AI tool reach it

**Claude Code, Codex, Gemini CLI and other terminal agents** need nothing:
they run `jit job run notion-export` in the terminal. A sandboxed one needs
the service's socket allowed ([Calling jit from a sandbox](./sandboxed-callers.md)).

**Claude Desktop (Cowork) and Cursor** reach jobs through `jit mcp`, a small
MCP server the app starts on your Mac. Connect an app once:

- **In JitPass:** AI Jobs, then **Connect** next to the app in *AI apps that
  can ask*. Claude Desktop also has a **Connect** on its card in the AI
  Agents window, and setup offers it on its last screen.
- **In a terminal:**

  ```sh
  jit mcp install                  # Claude Desktop
  jit mcp install --client cursor  # Cursor
  ```

Then **quit and reopen the app**: it reads its MCP servers when it starts.
Connecting approves nothing. It adds one entry, `jit`, to the app's config
(`~/Library/Application Support/Claude/claude_desktop_config.json`, or
`~/.cursor/mcp.json`), after saving a backup beside it, and changes nothing
else. `jit mcp status` says whether it is set up; `jit mcp uninstall` takes
it out again.

The app's agent then has three tools: `list_jobs`, `run_job` and
`request_job`. Ask it, in plain words, to run the job.

## 3. What happens when it runs

- A job approved to ask **each time** shows a Touch ID naming who asked. With
  JitPass running you first see the job's own sheet (the command, the folder,
  who asked), press Allow, and confirm with Touch ID.
- The service checks the job's folder first. If anything changed since you
  approved it, a script, a library, the profile file, even a file swapped
  and put back, **the job stops** and says which file. It stays stopped until
  you look and approve it again (**Review…** in AI Jobs, or `jit job allow
  NAME --replace -- …`).
- The tool gets the exit code and the output. Every secret value, and its
  common encodings, is hidden. With `--output DIR` (terminal only), files the
  job wrote there are listed by path.

## 4. When the tool asks for a job that does not exist

The agent can propose one with `request_job`. With JitPass running you get a
notification, and the proposal opens as a pre-filled New AI Job sheet with
the agent's reason shown as its own words. You approve it with Touch ID or
dismiss it. Without JitPass, the agent is told the exact `jit job allow`
line to ask you to run. A proposal never creates anything, and never runs
without asking: that choice is only yours.

## Changing a job

**Edit…** on a job's row opens the same sheet, filled in from the job. The
name stays; anything else can change, and approving the change is one Touch
ID. Until then the job runs as it was. A stopped job is changed from its
**Review…**, which shows what changed and can also remove it. In a terminal,
`jit job allow NAME --replace -- …` does the same.

## Jobs that run while you are away

Approve with `--ask never` (or *Never, until you remove it* on the sheet)
and the job runs with no Touch ID, even with the vault locked, using a key of
its own in your keychain. Removing the job deletes that key.

## What this does not protect

- **A script written to leak.** One you approved that sends its key
  somewhere, or prints it encoded in a way jit does not know. The fingerprint
  makes sure the code that runs is the code you read; it cannot make that
  code honest. Read what you approve.
- **Programs the job calls.** `git`, `curl` or a Homebrew tool it runs are
  trusted as installed.
- **What the job can do with its key.** A read-only token limits that; jit
  does not.

Every approval, run, refusal and removal is in `jit audit`. A stop and a
proposal also notify you, unless Settings › Notifications turns it off.

Design: [design/agent-jobs.md](../../design/agent-jobs.md).
