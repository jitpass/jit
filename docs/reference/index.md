---
title: Reference
description: Command reference, file locations, environment variables, and protocol details.
---

# Reference

- **[Command reference](./commands/jit.md)** - every command and flag,
  generated from the CLI itself (`jit <command> --help` has the same
  information at the terminal)
- **[File locations](./file-locations.md)** - where the vault, profiles,
  shims, and rewritten configs live
- **[Environment variables](./environment-variables.md)** - what jit reads,
  sets, and injects
- **[Audit NDJSON output](./audit-ndjson.md)** - the machine-readable
  finding schema
- **[Plumbing protocols](./plumbing.md)** - the commands other tools
  invoke (`aws-credential-process`, `k8s-exec-credential`,
  `terraform-credentials`, `docker-credential`)
