// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/job"
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
func (k presenceKey) FetchMEKCancel(reason string, _ <-chan struct{}) ([]byte, error) {
	return k.FetchMEK(reason)
}
func (presenceKey) Close() {}

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

// Out and back keeps where the value came from: the envelope's origin and
// group ride in the index while the value is a plain setting (review of #183).
func TestVaultMoveKeepsTheOrigin(t *testing.T) {
	r := newMoveRig(t)
	meta := vault.Meta{Class: vault.ClassDotenv, Origin: "~/code/billing-sync/.env", GroupID: "g1"}
	// A fresh path: the rig's own entry was stored without an origin, and a
	// rotation keeps the birth record it has.
	if err := r.v.SetWithMeta("billing/REPORT_FILE", []byte("out/report.csv"), meta); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.manifest, []byte("REPORT_FILE: billing/REPORT_FILE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"move-out", "move-in"} {
		if out, err := execVaultMove(t, dir, "billing/REPORT_FILE", "--yes"); err != nil {
			t.Fatalf("%s: %v\n%s", dir, err, out)
		}
	}
	info, err := r.v.Info("billing/REPORT_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if info.Origin != meta.Origin || info.GroupID != meta.GroupID {
		t.Errorf("after out and back: origin %q group %q, want %q %q", info.Origin, info.GroupID, meta.Origin, meta.GroupID)
	}
}

// A run that fails on its second value has already saved the first one's
// origin: the vault copy it removed was the only other record (review of
// #183).
func TestAFailedMoveKeepsWhatItMovedTraceable(t *testing.T) {
	r := newMoveRig(t)
	meta := vault.Meta{Class: vault.ClassDotenv, Origin: "~/code/billing-sync/.env", GroupID: "g1"}
	for _, p := range []string{"billing/FIRST_FILE", "billing/SECOND_FILE"} {
		if err := r.v.SetWithMeta(p, []byte("out/x.csv"), meta); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(r.manifest, []byte("FIRST_FILE: billing/FIRST_FILE\nSECOND_FILE: billing/SECOND_FILE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A folder where the second setting's file would go: its write fails.
	if err := os.MkdirAll(filepath.Join(r.root, settings.Dir, "billing", "SECOND_FILE"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := execVaultMove(t, "move-out", "billing/FIRST_FILE", "billing/SECOND_FILE", "--yes"); err == nil {
		t.Fatal("the second move was meant to fail")
	}
	if ok, _ := r.v.Exists("billing/FIRST_FILE"); ok {
		t.Fatal("precondition: the first value moved before the failure")
	}
	classes, err := settings.LoadClasses(r.root)
	if err != nil {
		t.Fatal(err)
	}
	if got := classes.SettingProvenance("billing/FIRST_FILE"); got.Origin != meta.Origin {
		t.Errorf("first value's origin after the failed run = %+v, want %q", got, meta.Origin)
	}
}

// An index that cannot be read refuses a move-out before Touch ID: moving
// out keeps each value's origin only there.
func TestMoveOutRefusesAnUnreadableIndex(t *testing.T) {
	r := newMoveRig(t)
	if err := os.WriteFile(filepath.Join(r.root, settings.ClassesFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execVaultMove(t, "move-out", "billing/EXPORT_SECRETS_FILE", "--yes"); err == nil {
		t.Fatal("move-out with an unreadable index succeeded")
	}
	if len(r.reasons) != 0 {
		t.Errorf("a refused move asked for Touch ID: %q", r.reasons)
	}
	if ok, _ := r.v.Exists("billing/EXPORT_SECRETS_FILE"); !ok {
		t.Error("a refused move removed the value")
	}
}

// A move out asks the service to carry the AI jobs that get the value along
// while both copies exist (the service compares them), and says what it did
// to each: carried, or stopped with the line that approves it again. Asked
// after the vault copy is gone, the service would have nothing to compare.
func TestVaultMoveOutCarriesAIJobsWhileBothCopiesExist(t *testing.T) {
	r := newMoveRig(t)
	const p = "billing/EXPORT_SECRETS_FILE"
	var inVault, inSettings bool
	origCarry, origList, origUse := carryMovedJobs, listJobsForMove, jobsMayUse
	t.Cleanup(func() { carryMovedJobs, listJobsForMove, jobsMayUse = origCarry, origList, origUse })
	jobsMayUse = func(string) bool { return true }
	carryMovedJobs = func(path string) ([]agent.JobCarry, error) {
		if path != p {
			t.Errorf("carry asked for %q, want %q", path, p)
		}
		inVault, _ = r.v.Exists(p)
		inSettings, _ = settings.New(r.root).Exists(p)
		return []agent.JobCarry{
			{Job: "billing-sync", Var: "EXPORT_SECRETS_FILE", Carried: true},
			{Job: "billing-report", Var: "EXPORT_SECRETS_FILE", Why: "the vault is locked"},
		}, nil
	}
	listJobsForMove = func() ([]agent.JobStatus, error) {
		return []agent.JobStatus{{Name: "billing-report", Dir: "/work/billing", Argv: []string{"./report.sh"}, Ask: "each-time", Profile: "billing"}}, nil
	}

	out, err := execVaultMove(t, "move-out", p, "--yes")
	if err != nil {
		t.Fatalf("move-out: %v\n%s", err, out)
	}
	if !inVault || !inSettings {
		t.Fatalf("carry asked with vault copy %v, setting %v; want both there", inVault, inSettings)
	}
	for _, want := range []string{
		"AI job billing-sync reads it from the setting now",
		"AI job billing-report stops until you approve it again: the vault is locked",
		"cd /work/billing && jit job allow billing-report --replace --profile billing -- ./report.sh",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	if _, err := execVaultMove(t, "move-in", p, "--yes"); err != nil {
		t.Fatal(err)
	}
	out, err = execVaultMove(t, "move-out", p, "--yes", "--format", "json")
	if err != nil {
		t.Fatalf("move-out json: %v\n%s", err, out)
	}
	var res settingMoveResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	jobs := res.Moved[0].Jobs
	if len(jobs) != 2 || !jobs[0].Carried || jobs[1].Carried || jobs[1].Approve == "" {
		t.Fatalf("jobs = %+v, want one carried and one stopped with its approve line", jobs)
	}
}

// A service that can't be asked never fails the move: the value is already
// in its setting, and the output says the jobs weren't checked.
func TestVaultMoveOutSaysWhenAIJobsWerentChecked(t *testing.T) {
	newMoveRig(t)
	orig, origUse := carryMovedJobs, jobsMayUse
	t.Cleanup(func() { carryMovedJobs, jobsMayUse = orig, origUse })
	jobsMayUse = func(string) bool { return true }
	carryMovedJobs = func(string) ([]agent.JobCarry, error) {
		return nil, errors.New(`agent: unknown op "job_carry"`)
	}
	out, err := execVaultMove(t, "move-out", "billing/EXPORT_SECRETS_FILE", "--yes")
	if err != nil {
		t.Fatalf("move-out: %v\n%s", err, out)
	}
	if !strings.Contains(out, "AI jobs weren't checked (the jit service is older than this jit)") {
		t.Errorf("output lacks the unchecked note:\n%s", out)
	}
}

// A value no AI job gets moves without asking the service or saying anything
// about jobs: the job list on disk answers first.
func TestVaultMoveOutAsksNoServiceWhenNoJobGetsTheValue(t *testing.T) {
	r := newMoveRig(t)
	orig := carryMovedJobs
	t.Cleanup(func() { carryMovedJobs = orig })
	asked := false
	carryMovedJobs = func(string) ([]agent.JobCarry, error) {
		asked = true
		return nil, errors.New("no service")
	}
	if err := os.WriteFile(job.StorePath(r.root), []byte(`{"version":1,"jobs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := execVaultMove(t, "move-out", "billing/EXPORT_SECRETS_FILE", "--yes")
	if err != nil {
		t.Fatalf("move-out: %v\n%s", err, out)
	}
	if asked || strings.Contains(out, "AI job") {
		t.Fatalf("asked the service %v, output:\n%s", asked, out)
	}
}
