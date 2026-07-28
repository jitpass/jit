// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// TestPypircMountServesTheOriginalFileEndToEnd is the question every other
// pypirc test only approximates: after migration, does a program that opens
// ~/.pypirc actually get its credentials back?
//
// Everything below the CLI is real — a real agent, a real FIFO at the real
// path, a real vault write, and a real open()/read() of the mount. Only the
// Touch ID challenge is stubbed (fakeMEKFetcher, this project's established
// pattern for the one boundary that cannot be scripted).
//
// This matters more here than for most categories: twine, uv and poetry read
// ~/.pypirc directly, so a template that renders even one byte differently
// fails an upload against a file that looks perfectly correct — the hardest
// failure mode to diagnose from the symptom.
func TestPypircMountServesTheOriginalFileEndToEnd(t *testing.T) {
	const original = `[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDk0YTUxZmE0

[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password = Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA
`
	root := t.TempDir() // stands in for ~/.jit
	home := t.TempDir()
	path := migrate.PypircPath(home)
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "a.sock")
	mek := bytes.Repeat([]byte{0x24}, 32)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: mek} }, time.Minute)
	var stdout, stderr bytes.Buffer
	mounts := &mountManager{root: root, keyWrapper: server, stdout: &stdout, stderr: &stderr}

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: server, RecipientID: hostname}

	// The real migration: vault writes, profile manifest, template, FIFO swap.
	result, err := migrate.ApplyPypirc(v, root, path)
	if err != nil {
		t.Fatalf("ApplyPypirc: %v", err)
	}
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
		MountPath: path, ProfilePath: result.ProfilePath, TemplatePath: result.TemplatePath,
	}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	// Nothing on disk may still hold a credential.
	onDisk, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	for _, secret := range []string{"pypi-AgEIcHlwaS5vcmcCJDk0YTUxZmE0", "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"} {
		if bytes.Contains(onDisk, []byte(secret)) {
			t.Errorf("template still holds the plaintext secret %q", secret)
		}
	}

	// A read with no grant gets a decoy, never the real credential.
	mounts.start()
	waitForMountServing(t, mounts, path)
	got := readMountOnceWithTimeout(t, path, 2*time.Second)
	if bytes.Contains(got, []byte("Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA")) {
		t.Fatalf("mount served the real credential with no grant: %q", got)
	}

	// And with the run-scoped grant, the file comes back byte-for-byte.
	mounts.mu.Lock()
	sm := mounts.served[path]
	revealed := string(sm.real)
	mounts.mu.Unlock()
	if revealed != original {
		t.Errorf("what the mount serves under a grant is not the original file.\ngot:  %q\nwant: %q", revealed, original)
	}
	if !strings.Contains(revealed, "username = ci-publisher") {
		t.Error("non-secret lines must survive the round trip")
	}
}
