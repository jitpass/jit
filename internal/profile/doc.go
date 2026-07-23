// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Package profile implements named profile manifests (RFC.md Pillar IV): a
// small, git-safe YAML file under .jit/profiles/ that maps environment
// variable names to vault secret paths, decoupled from the vault tree
// itself. jit doctor (internal/cli/doctor.go) is the first consumer —
// it loads profiles from this package and checks each referenced path
// actually exists in the vault. See task #8.
//
// Load(root, name) also falls back to GlobalRoot() (os.UserHomeDir()) when
// a profile isn't found relative to root — for secrets not tied to one
// project directory (shell-config/MCP/AWS/kubeconfig migrations, GAPS.md
// #7/#8), where the command that resolves them (a new shell, an MCP
// host's subprocess, the AWS CLI, kubectl) can't be relied on to start
// from any particular working directory.
//
// ListAll/LoadWithScope surface which store (project or global) a profile
// was found in, for jit status --secrets, jit doctor, and the --profile
// completions — inspection surfaces that only ever report names and vault
// paths, never secret values.
package profile
