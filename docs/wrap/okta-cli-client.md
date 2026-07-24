---
title: Wrap the Okta CLI (okta-cli-client) with jit
description: Keep your Okta API token out of ~/.okta/okta.yaml - injected as OKTA_CLIENT_TOKEN just-in-time.
---

# okta-cli-client - Okta CLI

The [Okta CLI](https://github.com/okta/okta-cli-client) authenticates to the
Okta management API with an **API token** (an SSWS admin token). It reads that
token from `~/.okta/okta.yaml` (under `okta.client.token`) or from the
`OKTA_CLIENT_TOKEN` environment variable. Wrapping moves the token into the
vault and injects it as `OKTA_CLIENT_TOKEN` into each `okta-cli-client`
invocation only.

## Wrap it

```sh
jit wrap okta-cli-client
```

jit reads `okta.client.token` from `~/.okta/okta.yaml` if present, stores it at
`wrap-okta-cli-client/OKTA_CLIENT_TOKEN`, scrubs the plaintext (original backed
up encrypted), and installs the `~/.jit/shims/okta-cli-client` shim plus the
`wrap-okta-cli-client` profile.

No `~/.okta/okta.yaml`? Provide the token first, then wrap:

```sh
jit vault set wrap-okta-cli-client/OKTA_CLIENT_TOKEN   # a token from your Okta admin console
jit wrap okta-cli-client
```

## Verify

```sh
okta-cli-client group lists
```

## How it works

The shim injects `OKTA_CLIENT_TOKEN` from the vault into each
`okta-cli-client` process - the CLI's documented, highest-priority credential.
Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo okta-cli-client
```

## Notes

- **This is `okta-cli-client`, not `okta`.** The older `okta`/`ok` CLI from
  cli.okta.com was deprecated in July 2025 and stores no durable API token, so
  it isn't wrappable. This page is for the official replacement.
- **Beta tool.** `okta-cli-client` is pre-1.0 and may change its interface; the
  `OKTA_CLIENT_TOKEN` env var and `okta.client.token` path are stable today.
- **User-authored file.** Nothing writes `~/.okta/okta.yaml` for you (unlike a
  `login` flow), so many setups just export `OKTA_CLIENT_TOKEN` directly. jit
  handles both: it auto-migrates the file when it exists, else `jit vault set`.
- **OAuth mode not covered.** okta-cli-client can instead authenticate with an
  RSA `privateKey` (`authorizationMode: PrivateKey`) in the same YAML. That's a
  different credential type; jit wraps only the API-token path. `orgUrl` is a
  non-secret identifier and is not vaulted.
