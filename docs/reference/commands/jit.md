## jit

Local-first developer secret runtime

### Synopsis

jit finds plaintext secrets exposed on your machine and gives you a one-command way to fix it, without ever putting them back on disk in plaintext. See https://github.com/jitpass/jit for details.

Start with `jit audit` (strictly read-only), then `jit migrate --dry-run` to preview the guided fix for everything it found.

```
jit
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command
* [jit audit](jit_audit.md)	 - Scan for plaintext secrets exposed on this machine (read-only)
* [jit aws-credential-process](jit_aws-credential-process.md)	 - Print AWS credential_process JSON for a migrated profile
* [jit completion](jit_completion.md)	 - Generate the autocompletion script for the specified shell
* [jit docker-credential](jit_docker-credential.md)	 - Implement Docker's credential-helper protocol for migrated registry logins
* [jit doctor](jit_doctor.md)	 - Verify every secret a profile references actually exists in the vault
* [jit export](jit_export.md)	 - Print shell export statements for a profile's secrets
* [jit k8s-exec-credential](jit_k8s-exec-credential.md)	 - Print a Kubernetes ExecCredential JSON for a migrated profile
* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit audit reports
* [jit profile](jit_profile.md)	 - Inspect profile manifests (names and vault paths only, never secret values)
* [jit run](jit_run.md)	 - Execute a command with a profile's secrets injected into its environment
* [jit sops-age-key](jit_sops-age-key.md)	 - Print the SOPS age private key from a migrated profile
* [jit status](jit_status.md)	 - One-shot overview of vault, agent, profile, and mount health
* [jit terraform-credentials](jit_terraform-credentials.md)	 - Implement Terraform's credentials-helper protocol for a migrated token
* [jit unmount](jit_unmount.md)	 - Reverse a live .env mount back into a plain file
* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault
* [jit wrap](jit_wrap.md)	 - Wrap CLI tools so their tokens are injected just-in-time

