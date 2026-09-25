// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/jitpass/jit/internal/agent"
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

// A marker this jit can't finish (a move to a target it does not know, a
// line no jit writes, or a file it can't read) gets its own finding with
// no command, never the rotation's `jit vault rekey`: that refuses a move's
// marker (a loop) or, worse, would resume a rotation over a half-done move.
// Every command still refuses on it, and so does the rotation itself.
func TestUnparseableMoveMarkerFailsClosed(t *testing.T) {
	stubKeychain(t, keystore.Present)
	for _, c := range []struct {
		name, marker string
		unreadable   bool
		detail       string
	}{
		{"unknown target", "move sideways started 2026-09-25T10:00:00Z\n", false,
			`a move of the vault key this version of jit doesn't understand (to "sideways") is unfinished, so every command that changes the vault will refuse until it finishes.`},
		{"unrecognised line", "rotating since tuesday\n", false,
			"a change of the vault key this version of jit doesn't understand is unfinished, so every command that changes the vault will refuse until it finishes."},
		{"unreadable", "started 2026-09-25T10:00:00Z\n", true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := withFixtureHome(t)
			root := fixtureRoot(home)
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(rekeyMarkerPath(root), []byte(c.marker), 0o600); err != nil {
				t.Fatal(err)
			}
			if c.unreadable {
				if err := os.Chmod(rekeyMarkerPath(root), 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(rekeyMarkerPath(root), 0o600) })
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
				t.Errorf("reported as move_unfinished %q", vs.MoveUnfinished)
			}
			f := withFixes(gatherVaultIntegrityFindings(root, v))
			if len(f) != 1 || f[0].Kind != kindRekeyUnknown {
				t.Fatalf("want one rekey_unknown finding, got %+v", f)
			}
			if c.detail != "" && f[0].Detail != c.detail {
				t.Errorf("detail = %q, want %q", f[0].Detail, c.detail)
			}
			if c.unreadable && !strings.HasPrefix(f[0].Detail, "jit can't read the file that marks an unfinished change of the vault key (") {
				t.Errorf("detail = %q, want it to say the marker can't be read", f[0].Detail)
			}
			if len(f[0].Fixes) != 0 || strings.Contains(f[0].Action, "`") {
				t.Errorf("a marker no command can finish carries a command: action %q, fixes %+v", f[0].Action, f[0].Fixes)
			}
			if f[0].Kind.warning() {
				t.Error("every vault change is refused: a hard problem, not advisory")
			}
			refusal := rekeyMarkerRefusal(root)
			if refusal == nil || errors.Is(refusal, errRekeyInProgress) || strings.Contains(refusal.Error(), "`jit vault rekey") {
				t.Errorf("refusal = %v, want the honest sentence and no rekey command", refusal)
			}

			// The rotation and the move both refuse it, before any key.
			for _, args := range [][]string{{"vault", "rekey", "--yes"}, {"vault", "rekey", "--yes", "--wrapper", wrapperKeychain}} {
				t.Cleanup(func() {
					vaultRekeyYes, vaultRekeyWrapper = false, ""
					vaultRekeyCmd.Flags().Visit(func(fl *pflag.Flag) { fl.Changed = false })
				})
				var buf bytes.Buffer
				rootCmd.SetOut(&buf)
				rootCmd.SetErr(&buf)
				rootCmd.SetArgs(args)
				err := rootCmd.Execute()
				vaultRekeyYes, vaultRekeyWrapper = false, ""
				if err == nil || !strings.Contains(err.Error(), "doesn't understand") && !strings.Contains(err.Error(), "can't read") {
					t.Errorf("jit %s over this marker: %v, want the honest refusal", strings.Join(args, " "), err)
				}
			}
		})
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

// lostKeyFixture is a fixture vault holding paths, all sealed to a lost key
// that `jit vault init` has just set aside, with imports writing under a
// fake key that asks no one.
func lostKeyFixture(t *testing.T, paths ...string) (root string, v *vault.Vault) {
	t.Helper()
	home := withFixtureHome(t)
	for _, p := range paths {
		root = seedFixtureVault(t, p)
	}
	stubKeychain(t, keystore.Present)
	orig := openKeyStore
	openKeyStore = func(string) keystore.Store { return importStore{recordingStore{kind: keystore.KindKeychain}} }
	t.Cleanup(func() { openKeyStore = orig })
	plantSealedKeyFile(t, root)
	if err := vault.SetAsideLostSealedKey(root, time.Now()); err != nil {
		t.Fatal(err)
	}
	return root, fixtureVault(home)
}

// Review finding 10 (and 2 from the CLI's side): a lost-key record jit
// can't read must never go silent. Status says restore_pending, with why it
// couldn't check; doctor gives the vault_restore finding saying the same,
// with the way out (review 3, finding 2: `jit vault import --finish`); the
// export advice stays out.
func TestAnUncheckableLostKeyIsReportedAsPending(t *testing.T) {
	root, v := lostKeyFixture(t, "fixture/A")
	if err := os.WriteFile(filepath.Join(root, vault.LostSealedKeyFile+".envelopes"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	vs, err := gatherVaultStatus(v, root)
	if err != nil {
		t.Fatal(err)
	}
	decoded := vaultJSON(t, vs)
	if decoded["restore_pending"] != true {
		t.Errorf("status JSON restore_pending = %v, want true", decoded["restore_pending"])
	}
	if msg, _ := decoded["restore_check_error"].(string); !strings.Contains(msg, "unreadable") {
		t.Errorf("status JSON restore_check_error = %q, want why", msg)
	}
	var buf bytes.Buffer
	printStatusKeyRows(&buf, vs)
	if !strings.Contains(buf.String(), "couldn't check the vault for secrets sealed to a lost key: ") {
		t.Errorf("status text is silent about the failed check:\n%s", buf.String())
	}

	f := restoreFindings(t, root, v)
	if len(f) != 1 || !strings.HasPrefix(f[0].Detail, "couldn't check the vault for secrets sealed to a lost key: ") {
		t.Fatalf("want one vault_restore finding saying it couldn't check, got %+v", f)
	}
	if want := "`jit vault import --finish` once you've imported every recovery file you have"; f[0].Action != want {
		t.Errorf("action = %q, want %q", f[0].Action, want)
	}
	wantFix := []doctorFix{{
		Command: "jit vault import --finish",
		Argv:    []string{"vault", "import", "--finish"},
	}}
	if !reflect.DeepEqual(f[0].Fixes, wantFix) {
		t.Errorf("fixes = %+v, want %+v", f[0].Fixes, wantFix)
	}
	if !strings.Contains(buf.String(), "jit vault import --finish") {
		t.Errorf("status text gives no way out of the failed check:\n%s", buf.String())
	}
	if b := backupFindings(v, root); len(b) != 0 {
		t.Errorf("export advice while the restore can't be checked: %+v", b)
	}
}

// Review finding 8: the status text's backup row advised `jit vault export`
// under the restore row, advice the export can't follow while secrets are
// sealed to the lost key. Doctor was already silent.
func TestStatusTextGivesNoExportAdviceWhileARestoreIsPending(t *testing.T) {
	for _, vs := range []statusVault{
		{SecretsStored: 3, RestorePending: true},
		{SecretsStored: 3, RestorePending: true, ExportRecorded: true, ExportStale: true, ExportUnixTime: 1},
	} {
		var buf bytes.Buffer
		printStatusText(&buf, statusResult{Vault: vs}, time.Now())
		out := buf.String()
		if !strings.Contains(out, "jit vault import <file>") {
			t.Fatalf("the restore row is missing:\n%s", out)
		}
		if strings.Contains(out, "jit vault export") {
			t.Errorf("export advice while a restore is pending:\n%s", out)
		}
	}
}

// Review finding 9: the storage-format finding's export advice stays out
// while a restore is pending, for the same reason. A vault with a legacy
// (v1) envelope would otherwise get it.
func TestLegacyEnvelopeAdviceStaysOutWhileARestoreIsPending(t *testing.T) {
	home := withFixtureHome(t)
	plantLegacySecret(t, home, "legacy/old-key")
	plantVaultSecret(t, home, "modern/current")
	stubKeychain(t, keystore.Present)
	root := fixtureRoot(home)
	plantSealedKeyFile(t, root)
	if err := vault.SetAsideLostSealedKey(root, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range gatherVaultIntegrityFindings(root, fixtureVault(home)) {
		if f.Kind == kindLegacyEnvelope {
			t.Errorf("storage-format advice while a restore is pending: %+v", f)
		}
	}
}

// An rm-only cleanup settles too: importing what the recovery file held,
// then removing what it didn't, ends the restore.
func TestRemovingWhatARecoveryFileLackedSettlesTheRestore(t *testing.T) {
	root, v := lostKeyFixture(t, "fixture/A", "fixture/B")
	runImport(t, writeRecoveryFile(t, "correct horse battery", "fixture/A"), "correct horse battery")
	if vs, _ := gatherVaultStatus(v, root); !vs.RestorePending {
		t.Fatal("setup: fixture/B should still be pending")
	}

	prev := requireUserPresence
	requireUserPresence = func(string) error { return nil }
	t.Cleanup(func() { requireUserPresence = prev; vaultRmYes = false })
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rm", "-y", "fixture/B"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault rm: %v\n%s", err, buf.String())
	}
	if vs, _ := gatherVaultStatus(v, root); vs.RestorePending {
		t.Errorf("restore_pending after removing the last secret sealed to the lost key\n%s", buf.String())
	}
	if _, err := os.Stat(filepath.Join(root, vault.LostSealedKeyFile)); !os.IsNotExist(err) {
		t.Errorf("the lost key's file was not retired: %v", err)
	}
	if kept, _ := filepath.Glob(filepath.Join(root, vault.LostSealedKeyFile+"-*")); len(kept) == 0 {
		t.Error("the lost key's sealed file was deleted instead of kept")
	}
}

// Doctor hashes every envelope for the lost-key check: once per run, shared
// by the integrity and backup sections.
func TestDoctorChecksForALostKeyOnce(t *testing.T) {
	withFixtureCwd(t)
	lostKeyFixture(t, "fixture/A")
	orig := checkLostKey
	calls := 0
	checkLostKey = func(root string) lostKeyCheck { calls++; return orig(root) }
	t.Cleanup(func() { checkLostKey = orig })

	out, _ := execDoctor(t)
	if calls != 1 {
		t.Errorf("doctor ran the lost-key check %d times, want 1", calls)
	}
	if !strings.Contains(out, "sealed to a key this Mac no longer has") {
		t.Errorf("doctor did not report the pending restore:\n%s", out)
	}
}

// Review finding 7: `jit vault init` over a lost key drops the running
// service's session, as rekey does, so a service still holding the lost
// key stops sealing writes under it. Driven against a real agent.Server
// with a fake MEK fetch (the established boundary).
func TestVaultInitOverALostKeyLocksTheService(t *testing.T) {
	home := shortFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	orig := openKeyStore
	openKeyStore = func(string) keystore.Store {
		return recordingStore{kind: keystore.KindSecureEnclave, presence: keystore.KeyLost}
	}
	t.Cleanup(func() { openKeyStore = orig })

	socketPath := agent.SocketPath(root)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: bytes.Repeat([]byte{0x77}, 32)} }, time.Minute)
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()
	client := agent.NewClient(socketPath)
	if _, _, err := client.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "init"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault init: %v\n%s", err, buf.String())
	}
	if st, err := client.Status(); err != nil || st.Unlocked {
		t.Errorf("the service still holds a session after init replaced a lost key (unlocked=%v, err=%v)", st.Unlocked, err)
	}
}

// Review finding 1, the CLI half: a rotation that kept copies sealed to a
// lost key says so, rather than claiming every secret moved.
func TestRekeyReportsTheLostKeyCopiesItKept(t *testing.T) {
	var buf bytes.Buffer
	printKeptLostKeyCopies(&buf, []string{"a.enc", "_history/a/1.enc", "b.enc"})
	if want := "Left 3 files sealed to a lost key as they were: no key on this Mac opens them.\n"; buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
	buf.Reset()
	printKeptLostKeyCopies(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("nothing kept, yet: %q", buf.String())
	}
}

// runFinish runs `jit vault import --finish` with answer on stdin.
func runFinish(t *testing.T, answer string, extra ...string) (string, error) {
	t.Helper()
	t.Cleanup(func() { vaultImportFinish, vaultImportYes = false, false })
	vaultImportFinish, vaultImportYes, vaultImportStdin = false, false, false // flags persist across Execute
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(answer))
	rootCmd.SetArgs(append([]string{"vault", "import", "--finish"}, extra...))
	err := rootCmd.Execute()
	vaultImportFinish, vaultImportYes = false, false
	return buf.String(), err
}

// Review 3, finding 2: a lost-key record jit can't read settles nothing,
// so without a way out the restore stayed pending, status red, forever.
// `jit vault import --finish` is that way out: it asks first, lists the
// secrets that may still not open, renames the lost key's files (never
// deletes them), and clears the state.
func TestImportFinishSettlesARestoreTheRecordCantCheck(t *testing.T) {
	root, v := lostKeyFixture(t, "fixture/A", "fixture/B")
	snapshot := filepath.Join(root, vault.LostSealedKeyFile+".envelopes")
	if err := os.WriteFile(snapshot, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runImport(t, writeRecoveryFile(t, "correct horse battery", "fixture/A"), "correct horse battery")
	if !strings.Contains(out, "jit vault import --finish") {
		t.Errorf("the import that couldn't check gives no way out:\n%s", out)
	}

	// Declining changes nothing.
	out, err := runFinish(t, "n\n")
	if err != nil || !strings.Contains(out, "Aborted.") {
		t.Fatalf("declined --finish: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, vault.LostSealedKeyFile)); err != nil {
		t.Fatalf("a declined --finish retired the lost key: %v", err)
	}

	out, err = runFinish(t, "y\n")
	if err != nil {
		t.Fatalf("--finish: %v\n%s", err, out)
	}
	for _, want := range []string{
		"jit can't check which secrets still won't open: the record of secrets sealed to the lost key is unreadable",
		"1 secret was last changed before the key was lost, so may not open:\n  fixture/B\n",
		"Stop tracking the restore? The lost key's files are kept. [y/N] ",
		"Restore finished. The lost key's files are kept under a dated name.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--finish output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fixture/A") {
		t.Errorf("--finish lists a secret the import rewrote:\n%s", out)
	}
	vs, err := gatherVaultStatus(v, root)
	if err != nil {
		t.Fatal(err)
	}
	if vs.RestorePending || vs.RestoreCheckError != "" {
		t.Errorf("still pending after --finish: %+v", vs)
	}
	if f := restoreFindings(t, root, v); len(f) != 0 {
		t.Errorf("vault_restore after --finish: %+v", f)
	}
	for _, name := range []string{vault.LostSealedKeyFile, vault.LostSealedKeyFile + ".envelopes"} {
		kept, _ := filepath.Glob(filepath.Join(root, name+"-*"))
		if len(kept) != 1 {
			t.Errorf("%s was not kept under a dated name: %q", name, kept)
		}
	}
	if exists, _ := v.Exists("fixture/B"); !exists {
		t.Error("--finish removed a secret")
	}
}

// --finish is only for a record that can't say. While a readable record
// still lists secrets it refuses, naming them, and changes nothing: an
// import or `jit vault rm` settles those with proof. With no lost key it
// says so.
func TestImportFinishRefusesWhileTheRecordListsSecrets(t *testing.T) {
	root, _ := lostKeyFixture(t, "fixture/A")
	out, err := runFinish(t, "", "--yes")
	if err == nil || !strings.Contains(out, "1 secret is still sealed to the lost key:\n  fixture/A\n") {
		t.Fatalf("--finish over a readable record with secrets left: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, vault.LostSealedKeyFile)); err != nil {
		t.Fatalf("a refused --finish retired the lost key: %v", err)
	}
	if err := os.Rename(filepath.Join(root, vault.LostSealedKeyFile), filepath.Join(root, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if out, err := runFinish(t, "", "--yes"); err != nil || !strings.Contains(out, "No lost key's restore is pending.") {
		t.Errorf("--finish with no lost key: %v\n%s", err, out)
	}
	if _, err := runFinish(t, "", "some-file"); err == nil {
		t.Error("--finish accepted a file")
	}
}

// A keychain copy a move could not delete: status says keychain_copy_left
// with an amber row, doctor a vault_key_copy finding whose one fix is the
// command that removes it. Both from the same no-prompt check.
func TestKeychainCopyIsReported(t *testing.T) {
	stubKeychain(t, keystore.Present)
	w := newMoveWorld(t)
	w.startInKeychain()
	w.failDelete = errOwnerEdit
	if err := w.mover().toEnclave(); err != nil {
		t.Fatal(err)
	}
	orig := keychainCopyPresence
	keychainCopyPresence = func() keystore.Presence { return keystore.Present }
	t.Cleanup(func() { keychainCopyPresence = orig })
	v := &vault.Vault{Root: w.root, RecipientID: "test"}

	vs, err := gatherVaultStatus(v, w.root)
	if err != nil {
		t.Fatal(err)
	}
	decoded := vaultJSON(t, vs)
	if decoded["keychain_copy_left"] != true || decoded["key_store"] != "secure-enclave" {
		t.Errorf("status JSON = %v, want key_store secure-enclave and keychain_copy_left true", decoded)
	}
	if _, ok := decoded["move_unfinished"]; ok {
		t.Error("the finished move is still reported as unfinished")
	}
	var buf bytes.Buffer
	printStatusKeyRows(&buf, vs)
	if out := strings.Join(strings.Fields(buf.String()), " "); !strings.Contains(out, "an old copy is still in your keychain") || !strings.Contains(out, "jit vault rekey --wrapper secure-enclave") {
		t.Errorf("status text does not report the copy:\n%s", out)
	}

	findings := withFixes(gatherVaultIntegrityFindings(w.root, v))
	if len(findings) != 1 || findings[0].Kind != kindVaultKeyCopy {
		t.Fatalf("want one vault_key_copy finding, got %+v", findings)
	}
	f := findings[0]
	if want := "the vault key is in the Secure Enclave, but an old copy is still in your keychain, where any program running as you can read it."; f.Detail != want {
		t.Errorf("detail = %q, want %q", f.Detail, want)
	}
	wantFix := []doctorFix{{
		Command:  "jit vault rekey --wrapper secure-enclave",
		Argv:     []string{"vault", "rekey", "--wrapper", "secure-enclave"},
		Presence: true,
	}}
	if !reflect.DeepEqual(f.Fixes, wantFix) {
		t.Errorf("fixes = %+v, want %+v", f.Fixes, wantFix)
	}
	if f.Kind.warning() {
		t.Error("a readable copy of the enclave's key is a problem, not advisory")
	}

	// Gone: both go quiet.
	keychainCopyPresence = func() keystore.Presence { return keystore.Absent }
	if vs, _ := gatherVaultStatus(v, w.root); vs.KeychainCopyLeft {
		t.Error("status still reports a copy the keychain no longer holds")
	}
	if got := gatherVaultIntegrityFindings(w.root, v); len(got) != 0 {
		t.Errorf("doctor still reports: %+v", got)
	}
}
