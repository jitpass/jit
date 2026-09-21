---
title: Migrate JSON output
description: The one document behind jit migrate <path> --format json.
---

# Migrate JSON output

`jit migrate <path>... --format json --yes` runs the targeted migrate with
its text output captured and writes **one JSON document** to stdout: what
the run vaulted, what its agent-cache sweep removed and what it left, any
errors, and the text it would have printed. It exists so a program - the
JitPass app after a Protect - can say "NOTION_TOKEN is in the vault · 8
cached copies removed · 1 file left in Claude Code's transcripts" from
fields, not from parsed prose.

The document never contains a value: variable names and paths only, the
same contract as [scan's NDJSON](./scan-ndjson.md).

`--format json` needs `--yes` (a plan cannot be confirmed on a JSON
stream) and takes neither `--dry-run` (nothing to report as done) nor
`--clean` (its delete pass needs a person at its own prompt). The bare
`jit migrate` has no JSON form; its plan is interactive.

## Fields

| Field | Meaning |
|---|---|
| `targets` | the paths named on the command line, resolved to absolute paths, in order |
| `applied` | whether the plan ran; `false` when the targets held nothing to migrate, or the run stopped before touching anything |
| `vaulted` | the variable names this run stored, once each (`"NOTION_TOKEN"`, `"github.com/oauth_token"`) - the last segment of each vault path |
| `caches.removed` | each agent-cache file the sweep rewrote: `agent`, `area`, `path`, and `copies` (the credential spans removed from it) |
| `caches.left` | each cache file the sweep found a copy in and deliberately left: `agent`, `area`, `path`, `kind` (`live`, `binary`, `hardlink`) and `reason`, the sentence the text output prints |
| `errors` | every error the run reported, in order; the rest of the document is the partial result, which is real and undoable |
| `report` | the text output the run would have printed |

Slices are always present, `[]` when empty, never `null`.

## On error

The document is written even when the run fails: the edits made before
the failure are real, each is backed up, and `jit migrate undo` restores
them, so hiding them would strand the caller. The error is the last entry
of `errors`, and the exit status is non-zero.

## Example

```json
{
  "targets": ["/Users/me/notion/.env"],
  "applied": true,
  "vaulted": ["NOTION_TOKEN"],
  "caches": {
    "removed": [
      {"agent": "Claude Code", "area": "transcripts", "path": "/Users/me/.claude/projects/x/a.jsonl", "copies": 7},
      {"agent": "Claude Code", "area": "edit history", "path": "/Users/me/.claude/file-history/y", "copies": 1}
    ],
    "left": [
      {"agent": "Claude Code", "area": "transcripts", "path": "/Users/me/.claude/projects/x/live.jsonl",
       "kind": "live", "reason": "the agent wrote to it while jit was working; left alone"}
    ]
  },
  "errors": [],
  "report": "jit migrate, plan\n..."
}
```
