## jit

Local-first developer secret runtime

### Synopsis

jit finds plaintext secrets exposed on your machine and gives you a one-command way to fix it, without ever putting them back on disk in plaintext. See https://github.com/jitpass/jit for details.

Start with `jit scan` (strictly read-only), then `jit migrate <path> --dry-run` to preview the guided fix for a file it flagged.

```
jit [flags]
```

### Options

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit audit](jit_audit.md)	 - Show the audit log: what jit commands ran, when, by whom, and every unlock
* [jit aws-credential-process](jit_aws-credential-process.md)	 - Print AWS credential_process JSON for a migrated profile
* [jit clisso-capture](jit_clisso-capture.md)	 - Run clisso, capturing minted AWS credentials into the vault
* [jit completion](jit_completion.md)	 - Generate the autocompletion script for the specified shell
* [jit docker-credential](jit_docker-credential.md)	 - Implement Docker's credential-helper protocol for migrated registry logins
* [jit doctor](jit_doctor.md)	 - One-shot health check: profiles, secrets, service, backup, and wrap shims
* [jit export](jit_export.md)	 - Print shell export statements for a profile's secrets
* [jit git-credential](jit_git-credential.md)	 - Implement git's credential-helper protocol for migrated HTTPS logins
* [jit k8s-exec-credential](jit_k8s-exec-credential.md)	 - Print a Kubernetes ExecCredential JSON for a migrated profile
* [jit lock](jit_lock.md)	 - Lock jit's session immediately, without waiting for the TTL
* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)
* [jit run](jit_run.md)	 - Execute a command with a profile's secrets injected into its environment
* [jit scan](jit_scan.md)	 - Scan for plaintext secrets exposed on this machine (read-only)
* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)
* [jit sops-age-key](jit_sops-age-key.md)	 - Print the SOPS age private key from a migrated profile
* [jit status](jit_status.md)	 - One-shot overview of vault, service, secret, and mount health
* [jit terraform-credentials](jit_terraform-credentials.md)	 - Implement Terraform's credentials-helper protocol for a migrated token
* [jit uninstall](jit_uninstall.md)	 - Remove jit's service, shims, and binary (keeps your vault unless --purge)
* [jit unlock](jit_unlock.md)	 - Unlock jit's session now (prompts Touch ID if needed)
* [jit unmount](jit_unmount.md)	 - Reverse a live .env mount back into a plain file
* [jit upgrade](jit_upgrade.md)	 - Download the latest release, verify it, and swap this binary + service onto it
* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault
* [jit version](jit_version.md)	 - Print jit's version (same as `jit --version`)
* [jit wrap](jit_wrap.md)	 - Wrap CLI tools so their tokens are injected just-in-time

