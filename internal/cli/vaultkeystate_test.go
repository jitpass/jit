// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/vault"
)

// Two vault-key states the JitPass app reads from `jit status --format json`
// and `jit doctor --format json`: an unfinished move of the key, and a
// restore after a lost Secure Enclave key that has not brought every secret
// back. Nothing here reads a key: the move world and the fake store stand in
// for the keychain and the enclave.

// crashedMove leaves a real move marker, written by the mover itself, by
// crashing a move to target after its first step.
func crashedMove(t *testing.T, target string) *moveWorld {
	t.Helper()
	w := newMoveWorld(t)
	var m *keyMover
	if target == wrapperSecureEnclave {
		w.startInKeychain()
		m = w.mover()
	} else {
		w.startInEnclave()
		m = w.mover()
	}
	m.crash = func(string) error { return errors.New("crash") }
	run := m.toEnclave
	if target == wrapperKeychain {
		run = m.toKeychain
	}
	if err := run(); err == nil {
		t.Fatal("the injected crash did not stop the move")
	}
	if !rekeyInProgress(w.root) {
		t.Fatal("the crashed move left no marker")
	}
	return w
}

func vaultJSON(t *testing.T, vs statusVault) map[string]any {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestUnfinishedMoveIsReportedWithItsDirection(t *testing.T) {
	stubKeychain(t, keystore.Present)
	for _, c := range []struct {
		target, detail string
	}{
		{wrapperSecureEnclave, "moving the vault key into the Secure Enclave did not finish, so every command that changes the vault will refuse until it does."},
		{wrapperKeychain, "moving the vault key back to your keychain did not finish, so every command that changes the vault will refuse until it does."},
	} {
		t.Run(c.target, func(t *testing.T) {
			w := crashedMove(t, c.target)
			v := &vault.Vault{Root: w.root, RecipientID: "test"}

			vs, err := gatherVaultStatus(v, w.root)
			if err != nil {
				t.Fatal(err)
			}
			if got := vaultJSON(t, vs)["move_unfinished"]; got != c.target {
				t.Errorf("status JSON move_unfinished = %v, want %q", got, c.target)
			}

			findings := withFixes(gatherVaultIntegrityFindings(w.root, v))
			if len(findings) != 1 || findings[0].Kind != kindVaultMove {
				t.Fatalf("want one vault_move finding, got %+v", findings)
			}
			f := findings[0]
			if f.Detail != c.detail {
				t.Errorf("detail = %q, want %q", f.Detail, c.detail)
			}
			wantFix := []doctorFix{{
				Command:  "jit vault rekey --wrapper " + c.target,
				Argv:     []string{"vault", "rekey", "--wrapper", c.target},
				Presence: true,
			}}
			if !reflect.DeepEqual(f.Fixes, wantFix) {
				t.Errorf("fixes = %+v, want %+v", f.Fixes, wantFix)
			}
			if f.Kind.warning() {
				t.Error("an unfinished move blocks every vault write: a hard problem, not advisory")
			}

			// The refusal every other command gives names the same fix,
			// not `jit vault rekey`, which refuses to finish a move.
			if err := rekeyMarkerRefusal(w.root); err == nil || !strings.Contains(err.Error(), "`jit vault rekey --wrapper "+c.target+"`") {
				t.Errorf("refusal = %v, want it to name `jit vault rekey --wrapper %s`", err, c.target)
			}

			var buf bytes.Buffer
			printStatusKeyRows(&buf, vs)
			if out := strings.Join(strings.Fields(buf.String()), " "); !strings.Contains(out, "vault changes refused") || !strings.Contains(out, "jit vault rekey --wrapper "+c.target) {
				t.Errorf("status text does not report the move:\n%s", out)
			}
		})
	}
}

// A rotation's marker stays exactly the finding it always was, and says
// nothing about a move.
func TestRotationMarkerIsNotAMove(t *testing.T) {
	stubKeychain(t, keystore.Present)
	root := t.TempDir()
	if err := os.WriteFile(rekeyMarkerPath(root), []byte("started 2026-09-25T10:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &vault.Vault{Root: root, RecipientID: "test"}
	vs, err := gatherVaultStatus(v, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vaultJSON(t, vs)["move_unfinished"]; ok {
		t.Errorf("a rotation's marker reported a move: %+v", vs)
	}
	findings := gatherVaultIntegrityFindings(root, v)
	want := checkFinding{
		Kind:   kindRekey,
		Detail: "a master-key rotation is in progress, or was interrupted, so every command that writes to the vault will refuse until it finishes.",
		Action: "`jit vault rekey` to finish it",
	}
	if len(findings) != 1 || !reflect.DeepEqual(findings[0], want) {
		t.Fatalf("rotation finding changed: %+v", findings)
	}
	if !errors.Is(rekeyMarkerRefusal(root), errRekeyInProgress) {
		t.Error("a rotation's refusal changed")
	}
}

// A marker naming a target this jit does not know is reported the way any
// marker was before (every write refused, `jit vault rekey`), never as a
// move with a made-up direction, and every command still refuses on it.
func TestUnparseableMoveMarkerFailsClosed(t *testing.T) {
	stubKeychain(t, keystore.Present)
	root := t.TempDir()
	if err := os.WriteFile(rekeyMarkerPath(root), []byte("move sideways started 2026-09-25T10:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !rekeyInProgress(root) {
		t.Fatal("the marker no longer holds commands off")
	}
	v := &vault.Vault{Root: root, RecipientID: "test"}
	vs, err := gatherVaultStatus(v, root)
	if err != nil {
		t.Fatal(err)
	}
	if vs.MoveUnfinished != "" {
		t.Errorf("an unknown target was reported as move_unfinished %q", vs.MoveUnfinished)
	}
	if f := gatherVaultIntegrityFindings(root, v); len(f) != 1 || f[0].Kind != kindRekey {
		t.Fatalf("want the rekey finding, got %+v", f)
	}
	if !errors.Is(rekeyMarkerRefusal(root), errRekeyInProgress) {
		t.Error("an unparseable marker must still refuse with the rotation error")
	}
}

// importWrapper is a vault key that asks no one: a fake store hands it to
// `jit vault import` in place of the keychain.
type importWrapper struct{ *fakeKeyWrapper }

func (importWrapper) RequireUserPresence(string) error { return nil }

type importStore struct{ recordingStore }

func (importStore) NewWrapper() keystore.Wrapper { return importWrapper{newFakeKeyWrapper()} }

// writeRecoveryFile exports a vault holding exactly paths.
func writeRecoveryFile(t *testing.T, passphrase string, paths ...string) string {
	t.Helper()
	src := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	for _, p := range paths {
		if err := src.Set(p, []byte("restored "+p)); err != nil {
			t.Fatal(err)
		}
	}
	env, err := src.Export([]byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "recovery.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func runImport(t *testing.T, file, passphrase string) string {
	t.Helper()
	vaultImportYes, vaultImportStdin = true, true
	t.Cleanup(func() { vaultImportYes, vaultImportStdin = false, false })
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(passphrase + "\n"))
	rootCmd.SetArgs([]string{"vault", "import", "--yes", "--stdin", file})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault import: %v\n%s", err, buf.String())
	}
	return buf.String()
}

func restoreFindings(t *testing.T, root string, v *vault.Vault) []checkFinding {
	t.Helper()
	var out []checkFinding
	for _, f := range withFixes(gatherVaultIntegrityFindings(root, v)) {
		if f.Kind == kindVaultRestore {
			out = append(out, f)
		}
	}
	return out
}

// The lost-key restore end to end: `jit vault init` over a lost enclave key
// (simulated by the set-aside it performs), then imports. Until every
// secret sealed to the old key is back, status says restore_pending and
// doctor says vault_restore; an import whose file leaves some out keeps the
// state and names them; the one that completes it retires the lost key's
// file (kept, renamed) and clears both.
func TestLostKeyRestoreIsReportedUntilComplete(t *testing.T) {
	home := withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/A")
	seedFixtureVault(t, "fixture/B")
	seedFixtureVault(t, "fixture/C")
	stubKeychain(t, keystore.Present)
	orig := openKeyStore
	openKeyStore = func(string) keystore.Store { return importStore{recordingStore{kind: keystore.KindKeychain}} }
	t.Cleanup(func() { openKeyStore = orig })
	v := fixtureVault(home)

	plantSealedKeyFile(t, root)
	if err := vault.SetAsideLostSealedKey(root, time.Now()); err != nil {
		t.Fatal(err)
	}

	vs, err := gatherVaultStatus(v, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := vaultJSON(t, vs)["restore_pending"]; got != true {
		t.Fatalf("status JSON restore_pending = %v, want true", got)
	}
	f := restoreFindings(t, root, v)
	if len(f) != 1 {
		t.Fatalf("want one vault_restore finding, got %+v", f)
	}
	if want := "3 secrets were sealed to a key this Mac no longer has, so they can't be opened. A recovery file brings them back."; f[0].Detail != want {
		t.Errorf("detail = %q, want %q", f[0].Detail, want)
	}
	if want := "`jit vault import <file>` from a `jit vault export` backup"; f[0].Action != want {
		t.Errorf("action = %q, want %q", f[0].Action, want)
	}
	wantFix := []doctorFix{{
		Command:     "jit vault import <file>",
		Argv:        []string{"vault", "import", "<file>"},
		Destructive: true,
		Presence:    true,
		Needs:       "<file>",
	}}
	if !reflect.DeepEqual(f[0].Fixes, wantFix) {
		t.Errorf("fixes = %+v, want %+v", f[0].Fixes, wantFix)
	}
	if f[0].Kind.warning() {
		t.Error("secrets that can't be opened are a hard problem, not advisory")
	}
	// An export can't open those secrets, so no finding may advise one.
	for _, other := range append(backupFindings(v, root), gatherVaultIntegrityFindings(root, v)...) {
		if strings.Contains(other.Action, "jit vault export <file>`") && !strings.HasPrefix(other.Action, "`jit vault import") {
			t.Errorf("a finding advises an export that cannot work: %+v", other)
		}
	}

	// A recovery file without fixture/C: the import succeeds, C is named,
	// and nothing is settled or removed.
	out := runImport(t, writeRecoveryFile(t, "correct horse battery", "fixture/A", "fixture/B"), "correct horse battery")
	if !strings.Contains(out, "1 secret is still sealed to a key this Mac no longer has") || !strings.Contains(out, "fixture/C") {
		t.Errorf("the import did not name what it left behind:\n%s", out)
	}
	if exists, _ := v.Exists("fixture/C"); !exists {
		t.Error("the import removed a secret it could not restore")
	}
	if vs, _ := gatherVaultStatus(v, root); !vs.RestorePending {
		t.Error("restore_pending cleared while a secret is still sealed to the lost key")
	}
	if f := restoreFindings(t, root, v); len(f) != 1 || !strings.HasPrefix(f[0].Detail, "1 secret was sealed") {
		t.Errorf("after a partial import, want one finding for 1 secret, got %+v", f)
	}

	// The file that completes it clears the state and keeps the old key.
	runImport(t, writeRecoveryFile(t, "correct horse battery", "fixture/C"), "correct horse battery")
	vs, err = gatherVaultStatus(v, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vaultJSON(t, vs)["restore_pending"]; ok {
		t.Errorf("restore_pending still in the JSON after a complete restore: %+v", vs)
	}
	if f := restoreFindings(t, root, v); len(f) != 0 {
		t.Errorf("vault_restore after a complete restore: %+v", f)
	}
	if _, err := os.Stat(filepath.Join(root, vault.LostSealedKeyFile)); !os.IsNotExist(err) {
		t.Errorf("the lost key's file was not retired: %v", err)
	}
	if kept, _ := filepath.Glob(filepath.Join(root, vault.LostSealedKeyFile+"-*")); len(kept) == 0 {
		t.Error("the lost key's sealed file was deleted instead of kept")
	}
}

// Every vault command opens the vault through these two; under a move's
// marker they must name the move's own command.
func TestVaultCommandsRefuseAnUnfinishedMoveByName(t *testing.T) {
	home := withFixtureHome(t)
	root := fixtureRoot(home)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rekeyMarkerPath(root), []byte("move keychain started 2026-09-25T10:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, open := range map[string]func() (*vault.Vault, error){"openVault": openVault, "openVaultFreshAuth": openVaultFreshAuth} {
		if _, err := open(); err == nil || !strings.Contains(err.Error(), "`jit vault rekey --wrapper keychain`") {
			t.Errorf("%s under a move marker: %v, want the move's command", name, err)
		}
	}
}
