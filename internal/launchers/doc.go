// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package launchers is the launcher and reference map
// (design/doctor-repair.md, F1 and F2): one read-only answer to "what starts
// this profile" and "what points at this secret", for every profile jit can
// find from home.
//
// It exists because every delete decision needs that answer and jit used to
// have several partial ones. `jit vault rm` knew which profiles NAME a
// secret, not which configs LAUNCH the profile; an MCP entry's inner wrapper
// layer was invisible; ~/.aws/config and the kubeconfig were read only for
// the jit path they record; the shell rc marker was read by nothing; and
// every check walked from cwd, so a project store or config outside it did
// not exist. The Remove Secrets incident that design doc opens with is what
// that gap costs.
//
// # What is read
//
//   - Profiles: cwd's own store, the global store (~/.jit/profiles, always),
//     every project store under home (a directory holding .jit), and any
//     manifest the mount registry names outside those. Each manifest is
//     loaded, and its .source owner list read (migrate.ProfileOwners).
//   - Launchers that name a profile BY NAME: MCP entries (every wrapper layer
//     of a nested entry, not only the outer one), `credential_process` in
//     ~/.aws/config, kubeconfig exec args, env-wraps in ~/.jit/wrap.json and
//     `jit export --profile` lines in the shell rc files themselves.
//   - Launchers tied to a profile some other way: a registered mount (by
//     manifest path), the docker/git/terraform/cargo helper scripts (by
//     profile-name prefix: a helper derives its profile per request), and a
//     project store (a project profile is launched by `jit run` from inside
//     its project, which nothing on disk records).
//   - Pointer files: jit's own header-marked in-place pointer files, found
//     through the undo index and the home walk, plus ~/.clisso.yaml. These
//     point at vault PATHS, not profiles.
//
// A launcher names a profile the way `jit run` resolves one, project first:
// a global profile takes every launcher naming it, a project profile only
// launchers inside its own project. A by-name launcher that resolves to no
// profile at all is Broken (the future `launcher_broken` finding). A pointer
// naming a secret the vault lacks is a MissingPointer, when the caller
// supplies a way to ask the vault.
//
// # Discovery from home, never from cwd, never from /
//
// The walk always starts at home (F2), prunes exactly what migrate's own
// walks prune plus the Trash (a trashed project launches nothing), and
// refuses a home of "/": walking the whole disk finds every config twice
// through /System/Volumes/Data. Configs no home walk reaches are fixed
// files: Claude Desktop's config and ~/.claude.json (audit's list), VS
// Code's user mcp.json and its per-profile copies (under ~/Library, pruned
// by name), and Windsurf's ~/.codeium/windsurf/mcp_config.json. Coverage
// records whether the walk read home and which directories it could not
// enter. A "nothing launches it" verdict is only honest when it did both.
//
// # Strict and lenient
//
// Every source that fails to read is recorded as a SourceError, never
// silently skipped. A lenient caller (a report) gets the map and the list.
// A strict caller (anything that deletes on the answer) passes Strict and
// gets an error instead of a map, because a skipped file would make what it
// names look unused. Map.Err picks out chosen sources, for a caller strict
// about some and not others.
//
// The discovery set is not exhaustive and never claims to be: scripts,
// aliases, cron jobs and a bare `jit run` typed at a prompt launch profiles
// nothing on disk records. The map says "no known launcher", never "unused".
//
// # What it deliberately does not read
//
// $AWS_CONFIG_FILE and $KUBECONFIG: no jit writer honours them, so a file
// they name was never rewritten by jit. Grant-wraps (`jit run --with`) and
// capture-wraps (clisso) in wrap.json name a global mount or a capture
// command, not a profile: the mount is counted through the registry, and
// clisso's pointers through ~/.clisso.yaml.
package launchers
