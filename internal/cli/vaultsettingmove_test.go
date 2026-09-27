// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

// presenceKey is a test keychain key that records each Touch ID reason.
type presenceKey struct {
	kw      *fakeKeyWrapper
	reasons *[]string
}

func (k presenceKey) WrapKey(dek []byte) ([]byte, error) { return k.kw.WrapKey(dek) }
func (k presenceKey) UnwrapKey(w []byte) ([]byte, error) { return k.kw.UnwrapKey(w) }
func (k presenceKey) RequireUserPresence(reason string) error {
	*k.reasons = append(*k.reasons, reason)
	return nil
}
func (k presenceKey) FetchMEK(string) ([]byte, error) { return append([]byte(nil), k.kw.key...), nil }
func (presenceKey) Close()                            {}

// moveRig is a fixture home with a vault under a recording key, and one
// global profile naming billing/EXPORT_SECRETS_FILE.
type moveRig struct {
	root, manifest string
	v              *vault.Vault
	reasons        []string
}

func newMoveRig(t *testing.T) *moveRig {
	t.Helper()
	home := withFixtureHome(t)
	withFixtureCwd(t)
	r := &moveRig{}
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	r.root = root
	kw := newFakeKeyWrapper()
	orig := openKeyStore
	t.Cleanup(func() { openKeyStore = orig })
	openKeyStore = func(rt string) keystore.Store {
		return keystore.OpenTesting(rt, presenceKey{kw: kw, reasons: &r.reasons})
	}
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		t.Fatal(err)
	}
	r.v = &vault.Vault{Root: root, KeyWrapper: kw, RecipientID: deviceID}
	if err := r.v.Set("billing/EXPORT_SECRETS_FILE", []byte("exports/secrets.csv")); err != nil {
		t.Fatal(err)
	}
	r.manifest, err = profile.Path(home, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(r.manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.manifest, []byte("EXPORT_SECRETS_FILE: billing/EXPORT_SECRETS_FILE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func execVaultMove(t *testing.T, args ...string) (string, error) {
	t.Helper()
	settingMoveYes, settingMoveFormat = false, "text"
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs(append([]string{"vault"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

func (r *moveRig) entry(t *testing.T) string {
	t.Helper()
	p, err := profile.LoadFile(r.manifest)
	if err != nil {
		t.Fatal(err)
	}
	return p["EXPORT_SECRETS_FILE"]
}

// Out and back: the value never changes, only where it is kept, and each
// direction is its own Touch ID naming the value and its profile.
func TestVaultMoveOutAndBackIn(t *testing.T) {
	r := newMoveRig(t)
	out, err := execVaultMove(t, "move-out", "billing/EXPORT_SECRETS_FILE", "--yes", "--format", "json")
	if err != nil {
		t.Fatalf("move-out: %v\n%s", err, out)
	}
	var res settingMoveResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	if len(res.Moved) != 1 || res.Moved[0].Scan != "setting" || res.Moved[0].Profiles[0] != "billing" {
		t.Errorf("moved = %+v", res.Moved)
	}
	if got := r.entry(t); got != settings.Pointer("billing/EXPORT_SECRETS_FILE") {
		t.Errorf("manifest entry after move-out = %q, want the setting pointer", got)
	}
	if ok, _ := r.v.Exists("billing/EXPORT_SECRETS_FILE"); ok {
		t.Error("the vault still holds the value after move-out")
	}
	if got, err := settings.New(r.root).Get("billing/EXPORT_SECRETS_FILE"); err != nil || string(got) != "exports/secrets.csv" {
		t.Errorf("setting = %q, %v", got, err)
	}
	if len(r.reasons) != 1 || r.reasons[0] != "move EXPORT_SECRETS_FILE out of the vault (billing)" {
		t.Errorf("Touch ID reasons = %q", r.reasons)
	}

	if out, err := execVaultMove(t, "move-in", "billing/EXPORT_SECRETS_FILE", "--yes"); err != nil {
		t.Fatalf("move-in: %v\n%s", err, out)
	}
	if got := r.entry(t); got != "billing/EXPORT_SECRETS_FILE" {
		t.Errorf("manifest entry after move-in = %q, want the vault path", got)
	}
	if got, err := r.v.Get("billing/EXPORT_SECRETS_FILE"); err != nil || string(got) != "exports/secrets.csv" {
		t.Errorf("vault after move-in = %q, %v", got, err)
	}
	if ok, _ := settings.New(r.root).Exists("billing/EXPORT_SECRETS_FILE"); ok {
		t.Error("the setting is still there after move-in")
	}
	if len(r.reasons) != 2 || r.reasons[1] != "move EXPORT_SECRETS_FILE into the vault (billing)" {
		t.Errorf("Touch ID reasons = %q, want a second, its own", r.reasons)
	}
}

// A value no profile names is refused before Touch ID: moving it would only
// move where it is forgotten.
func TestVaultMoveOutRefusesAnUnnamedValue(t *testing.T) {
	r := newMoveRig(t)
	if err := r.v.Set("billing/LOOSE", []byte("x")); err != nil {
		t.Fatal(err)
	}
	_, err := execVaultMove(t, "move-out", "billing/LOOSE", "--yes")
	if err == nil || !strings.Contains(err.Error(), "no profile names billing/LOOSE") {
		t.Fatalf("move-out of an unnamed value = %v", err)
	}
	if len(r.reasons) != 0 {
		t.Errorf("a refused move asked for Touch ID: %q", r.reasons)
	}
	if ok, _ := r.v.Exists("billing/LOOSE"); !ok {
		t.Error("a refused move removed the value")
	}
}

// Without --yes the question leads with the risk, and a no moves nothing.
func TestVaultMoveOutAsksFirst(t *testing.T) {
	r := newMoveRig(t)
	out, err := execVaultMove(t, "move-out", "billing/EXPORT_SECRETS_FILE")
	if err != nil {
		t.Fatalf("move-out: %v", err)
	}
	if !strings.Contains(out, "Any program on this Mac can then read it") || !strings.Contains(out, "Nothing moved.") {
		t.Errorf("output = %q", out)
	}
	if len(r.reasons) != 0 || r.entry(t) != "billing/EXPORT_SECRETS_FILE" {
		t.Error("a declined move asked for Touch ID or moved the value")
	}
}

// The listing the Vault window's Settings section reads: path, value, and
// who names it.
func TestVaultSettingsListsWhatMovedOut(t *testing.T) {
	newMoveRig(t)
	if out, err := execVaultMove(t, "move-out", "billing/EXPORT_SECRETS_FILE", "--yes"); err != nil {
		t.Fatalf("move-out: %v\n%s", err, out)
	}
	vaultSettingsFormat = "text"
	out, err := execVaultMove(t, "settings", "--format", "json")
	if err != nil {
		t.Fatalf("vault settings: %v\n%s", err, out)
	}
	var res vaultSettingsResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(res.Settings) != 1 {
		t.Fatalf("settings = %+v", res.Settings)
	}
	st := res.Settings[0]
	if st.Path != "billing/EXPORT_SECRETS_FILE" || st.Value != "exports/secrets.csv" || len(st.UsedBy) != 1 || st.UsedBy[0] != "billing" {
		t.Errorf("setting = %+v", st)
	}
}
