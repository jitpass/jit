---
title: Tech stack
description: Implementation choices and their rationale - dependencies, crypto, IPC, and platform notes.
---

# Tech stack

The full document lives at **[TECH_STACK.md](../../TECH_STACK.md)** in the
repo root: language and toolchain choices, the dependency map by concern
(CLI, crypto/envelope encryption, Secure Enclave/Keychain, agent IPC,
process lineage, credential-helper protocols), rejected alternatives,
build/signing/distribution, and future-platform notes.

The one-paragraph version: jit is Go (CGO for the macOS
Keychain/Secure Enclave pieces), cobra for the CLI, with a deliberately
minimal dependency set - most of the interesting machinery (envelope
encryption, unix-socket agent with peer-credential caller identification,
named-pipe mounts, PATH shims) is in `internal/`, and each risky design
choice was validated by a research spike under `spike/` before it shipped.
