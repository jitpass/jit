// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Spike: can `jit` serve a cargo registry token through cargo's stable
// credential-provider mechanism (cargo 1.74+), so `jit migrate
// ~/.cargo/credentials.toml` can be a Tier 2 native hook (like AWS's
// credential_process and Terraform's credentials_helper) instead of a
// FIFO template mount?
//
// Questions this answers empirically (see FINDINGS.md for the verdicts):
//  1. Does `cargo:token-from-stdout <command>` invoke the command and send
//     its stdout as the Authorization header on an API operation?
//  2. Precedence: with both `cargo:token` (credentials.toml) and
//     token-from-stdout configured, which token does cargo send?
//  3. Does an empty/absent credentials.toml fall through to the provider?
//  4. What does `cargo login` do when only token-from-stdout is configured?
//
// Method: a local HTTP server plays a minimal sparse registry (config.json
// + the owners API endpoint) and records every Authorization header; cargo
// runs with a scratch CARGO_HOME pointing at it via `cargo owner --list`,
// an API operation that must send the token.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type authLog struct {
	mu      sync.Mutex
	headers []string
	paths   []string
}

func (a *authLog) record(r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.headers = append(a.headers, r.Header.Get("Authorization"))
	a.paths = append(a.paths, r.URL.Path)
}

func (a *authLog) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.headers, a.paths = nil, nil
}

func (a *authLog) summary() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var b strings.Builder
	for i, p := range a.paths {
		fmt.Fprintf(&b, "  %s -> Authorization: %q\n", p, a.headers[i])
	}
	return b.String()
}

func main() {
	log := &authLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		switch {
		case r.URL.Path == "/index/config.json":
			fmt.Fprintf(w, `{"dl":"%s/dl","api":"%s","auth-required":true}`, srvURL(r), srvURL(r))
		case strings.HasSuffix(r.URL.Path, "/owners"):
			fmt.Fprint(w, `{"users":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	work, err := os.MkdirTemp("", "cargo-cred-spike")
	must(err)
	defer os.RemoveAll(work)

	cargoHome := filepath.Join(work, "cargo-home")
	must(os.MkdirAll(cargoHome, 0o700))

	// The provider command cargo will run: prints a fixed token, and logs
	// each invocation so we can tell the provider ran (vs a cached token).
	tokScript := filepath.Join(work, "tok.sh")
	tokLog := filepath.Join(work, "tok.log")
	must(os.WriteFile(tokScript, []byte("#!/bin/sh\necho invoked >> "+tokLog+"\necho jit-served-token-from-stdout\n"), 0o700)) // #nosec G306 -- must be executable

	baseConfig := fmt.Sprintf("[registries.testreg]\nindex = \"sparse+%s/index/\"\n", srv.URL)

	scenario := func(name, extraConfig, credentials string, args ...string) {
		log.reset()
		_ = os.Remove(tokLog)
		must(os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(baseConfig+extraConfig), 0o600))
		credPath := filepath.Join(cargoHome, "credentials.toml")
		if credentials == "" {
			_ = os.Remove(credPath)
		} else {
			must(os.WriteFile(credPath, []byte(credentials), 0o600))
		}

		cmd := exec.Command("cargo", args...) // #nosec G204 -- spike, fixed args
		cmd.Env = append(os.Environ(), "CARGO_HOME="+cargoHome)
		out, err := cmd.CombinedOutput()
		fmt.Printf("=== %s\n$ cargo %s (err=%v)\n%s", name, strings.Join(args, " "), err, indent(string(out)))
		fmt.Printf("requests seen:\n%s", log.summary())
		if data, err := os.ReadFile(tokLog); err == nil { // #nosec G304 -- spike temp file
			fmt.Printf("provider invocations: %d\n", strings.Count(string(data), "invoked"))
		} else {
			fmt.Println("provider invocations: 0")
		}
		fmt.Println()
	}

	providers := "[registry]\nglobal-credential-providers = [\"cargo:token\", \"cargo:token-from-stdout " + tokScript + "\"]\n"

	// 1. Provider only, no credentials.toml: token must come from the script.
	scenario("provider-only", providers, "", "owner", "--list", "somecrate", "--registry", "testreg")

	// 2. Both sources hold a token: which wins? (docs say LATER entries in
	// global-credential-providers take precedence)
	scenario("both-sources", providers, "[registries.testreg]\ntoken = \"token-from-credentials-file\"\n",
		"owner", "--list", "somecrate", "--registry", "testreg")

	// 3. cargo:token FIRST and provider LAST but credentials empty of this
	// registry: falls through to the provider?
	scenario("fallthrough", providers, "[registries.otherreg]\ntoken = \"unrelated\"\n",
		"owner", "--list", "somecrate", "--registry", "testreg")

	// 4. Login under token-from-stdout only: expected to refuse (get-only
	// provider), which decides whether `cargo login` keeps working after a
	// jit migration that leaves ONLY the provider configured.
	stdoutOnly := "[registry]\nglobal-credential-providers = [\"cargo:token-from-stdout " + tokScript + "\"]\n"
	scenario("login-under-stdout-provider", stdoutOnly, "", "login", "--registry", "testreg", "ZZtestZZ")

	// 5. Baseline sanity: cargo:token alone with a credentials.toml token.
	scenario("credentials-baseline", "[registry]\nglobal-credential-providers = [\"cargo:token\"]\n",
		"[registries.testreg]\ntoken = \"token-from-credentials-file\"\n",
		"owner", "--list", "somecrate", "--registry", "testreg")

	// 6. What ENVIRONMENT does token-from-stdout's command get? Decides how
	// `jit cargo-token` would pick the right secret for multi-registry
	// setups (by index URL / registry name).
	envScript := filepath.Join(work, "env.sh")
	must(os.WriteFile(envScript, []byte("#!/bin/sh\nenv | grep -i cargo >> "+tokLog+"\necho envprobe-token\n"), 0o700)) // #nosec G306 -- must be executable
	scenario("stdout-provider-env", "[registry]\nglobal-credential-providers = [\"cargo:token-from-stdout "+envScript+"\"]\n", "",
		"owner", "--list", "somecrate", "--registry", "testreg")
	if data, err := os.ReadFile(tokLog); err == nil { // #nosec G304 -- spike temp file
		fmt.Printf("provider environment (CARGO_*):\n%s\n", indent(string(data)))
	}

	// 7. Full JSON-protocol provider: a probe that logs argv + every request
	// line cargo sends and answers get/login/logout. Decides whether a
	// `cargo-credential-jit` (via `jit cargo-credential`) can keep
	// `cargo login`/`logout` working post-migration, the way jit's
	// terraform-credentials helper keeps `terraform login` working.
	provScript := filepath.Join(work, "jsonprov.py")
	provLog := filepath.Join(work, "jsonprov.log")
	must(os.WriteFile(provScript, []byte(`#!/usr/bin/env python3
import sys, json
log = open(`+fmt.Sprintf("%q", provLog)+`, "a")
def w(o):
    sys.stdout.write(json.dumps(o)+"\n"); sys.stdout.flush()
log.write("argv: %r\n" % (sys.argv,)); log.flush()
w({"v":[1]})
for line in sys.stdin:
    log.write("recv: " + line); log.flush()
    req = json.loads(line)
    k = req.get("kind")
    if k == "get":
        w({"Ok":{"kind":"get","token":"json-provider-token","cache":"session","operation_independent":True}})
    elif k == "login":
        w({"Ok":{"kind":"login"}})
    elif k == "logout":
        w({"Ok":{"kind":"logout"}})
    else:
        w({"Err":{"kind":"operation-not-supported"}})
`), 0o700)) // #nosec G306 -- must be executable
	jsonProv := "[registry]\nglobal-credential-providers = [\"" + provScript + "\"]\n"
	scenario("json-provider-get", jsonProv, "", "owner", "--list", "somecrate", "--registry", "testreg")
	scenario("json-provider-login", jsonProv, "", "login", "--registry", "testreg", "ZZtestZZ")
	scenario("json-provider-logout", jsonProv, "", "logout", "--registry", "testreg")
	if data, err := os.ReadFile(provLog); err == nil { // #nosec G304 -- spike temp file
		fmt.Printf("json provider transcript:\n%s", indent(string(data)))
	}

	// 8. The "provider holds nothing" answer: respond {"Err":{"kind":
	// "not-found"}} on get — does cargo fall back to an EARLIER-listed
	// cargo:token, and is the error kind accepted at all? Decides what
	// `jit cargo-credential` answers for a registry jit never migrated.
	nfScript := filepath.Join(work, "notfound.py")
	must(os.WriteFile(nfScript, []byte(`#!/usr/bin/env python3
import sys, json
def w(o):
    sys.stdout.write(json.dumps(o)+"\n"); sys.stdout.flush()
w({"v":[1]})
for line in sys.stdin:
    w({"Err":{"kind":"not-found"}})
`), 0o700)) // #nosec G306 -- must be executable
	nfProviders := "[registry]\nglobal-credential-providers = [\"cargo:token\", \"" + nfScript + "\"]\n"
	scenario("notfound-falls-back", nfProviders, "[registries.testreg]\ntoken = \"token-from-credentials-file\"\n",
		"owner", "--list", "somecrate", "--registry", "testreg")
	scenario("notfound-no-fallback", "[registry]\nglobal-credential-providers = [\""+nfScript+"\"]\n", "",
		"owner", "--list", "somecrate", "--registry", "testreg")

	// 9. The internal-failure answer: {"Err":{"kind":"other","message":…}}
	// — is the message surfaced to the user? Decides how `jit
	// cargo-credential` reports a locked/denied vault for a registry it
	// DOES hold (where not-found would silently fall through to nothing).
	errScript := filepath.Join(work, "errother.py")
	must(os.WriteFile(errScript, []byte(`#!/usr/bin/env python3
import sys, json
def w(o):
    sys.stdout.write(json.dumps(o)+"\n"); sys.stdout.flush()
w({"v":[1]})
for line in sys.stdin:
    w({"Err":{"kind":"other","message":"vault locked: approve the jit Touch ID prompt and retry"}})
`), 0o700)) // #nosec G306 -- must be executable
	scenario("err-other-message", "[registry]\nglobal-credential-providers = [\""+errScript+"\"]\n", "",
		"owner", "--list", "somecrate", "--registry", "testreg")

	_ = time.Now // keep imports honest if scenarios change
}

func srvURL(r *http.Request) string { return "http://" + r.Host }

func indent(s string) string {
	if s == "" {
		return ""
	}
	return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ") + "\n"
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
