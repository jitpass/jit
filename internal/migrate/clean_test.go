// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/audit"
)

// A fake with a real vendor shape, same convention as loosefile_test.go —
// detected by the scanners, meaningless to push protection.
const cleanTestSecret = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"

func cleanScan(t *testing.T, home string, targets ...string) []audit.Finding {
	t.Helper()
	findings, _, err := audit.TargetedScan(audit.Config{HomeDir: home}, targets)
	if err != nil {
		t.Fatalf("TargetedScan: %v", err)
	}
	return findings
}

func TestPlanCleanClassesAndExclusion(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", "old", ".env")
	archivedEnv := filepath.Join(home, "backup", ".env")
	liveEnv := filepath.Join(home, "proj", ".env")
	for _, p := range []string{trashEnv, archivedEnv, liveEnv} {
		writeFile(t, p, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	}

	findings := cleanScan(t, home, trashEnv, archivedEnv, liveEnv)
	plan := PlanClean(home, findings, nil)

	byPath := map[string]audit.CleanClass{}
	for _, c := range plan.Candidates {
		byPath[c.Path] = c.Class
	}
	if byPath[trashEnv] != audit.CleanTrash {
		t.Errorf("trash file class = %q, want %q (candidates %v)", byPath[trashEnv], audit.CleanTrash, byPath)
	}
	if byPath[archivedEnv] != audit.CleanArchivedCopy {
		t.Errorf("archived file class = %q, want %q", byPath[archivedEnv], audit.CleanArchivedCopy)
	}
	if _, ok := byPath[liveEnv]; ok {
		t.Error("a live project .env must never be a clean candidate")
	}

	// A file this run's migrate phase acts on must drop out of the plan.
	excluded := PlanClean(home, findings, map[string]bool{archivedEnv: true})
	for _, c := range excluded.Candidates {
		if c.Path == archivedEnv {
			t.Error("excluded (being-migrated) file still planned for deletion")
		}
	}
}

func TestPlanCleanRefusesNonRegularFile(t *testing.T) {
	home := t.TempDir()
	trashFile := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashFile, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	findings := cleanScan(t, home, trashFile)

	// Swap the file for a symlink between scan and plan — the plan must
	// refuse it, not follow it.
	if err := os.Remove(trashFile); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(home, "victim")
	writeFile(t, victim, "innocent\n")
	if err := os.Symlink(victim, trashFile); err != nil {
		t.Fatal(err)
	}

	plan := PlanClean(home, findings, nil)
	if len(plan.Candidates) != 0 {
		t.Fatalf("symlinked path became a candidate: %+v", plan.Candidates)
	}
	found := false
	for _, s := range plan.LeftAlone {
		if s.Path == trashFile && strings.Contains(s.Reason, "aren't regular files") {
			found = true
		}
	}
	if !found {
		t.Errorf("no left-alone row for the symlink: %+v", plan.LeftAlone)
	}
}

// TestPlanCleanRefusesArchivedKeyVisibly: an archived private-key file is
// CleanNone (its body is never vaulted), but the scan report's archived note
// points its group at --clean — so the plan must REFUSE it out loud, not drop
// it, keeping the "a finding the scan showed never silently vanishes"
// invariant (code review, 2026-09-10).
func TestPlanCleanRefusesArchivedKeyVisibly(t *testing.T) {
	home := t.TempDir()
	archivedKey := filepath.Join(home, "backup", "id_rsa")
	writeFile(t, archivedKey, "-----BEGIN OPENSSH PRIVATE KEY-----\n"+
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZQ\n"+
		"-----END OPENSSH PRIVATE KEY-----\n")
	findings := cleanScan(t, home, archivedKey)
	plan := PlanClean(home, findings, nil)

	for _, c := range plan.Candidates {
		if c.Path == archivedKey {
			t.Fatal("an archived private key must never be a delete candidate")
		}
	}
	found := false
	for _, s := range plan.LeftAlone {
		if s.Path == archivedKey && strings.Contains(s.Reason, "private key material") {
			found = true
		}
	}
	if !found {
		t.Errorf("archived key silently dropped instead of refused: %+v", plan.LeftAlone)
	}
}

func TestApplyCleanArchivedRequiresVaultMatch(t *testing.T) {
	home := t.TempDir()
	archivedEnv := filepath.Join(home, "backup", ".env")
	writeFile(t, archivedEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, archivedEnv), nil)
	if len(plan.Candidates) != 1 {
		t.Fatalf("candidates = %+v, want the archived copy", plan.Candidates)
	}
	v := newTestVault(t)

	// Value not in the vault: refused, file untouched.
	out, err := ApplyClean(v, plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 0 || out.Errors() {
		t.Fatalf("outcome %+v, want a plain refusal", out)
	}
	if _, statErr := os.Stat(archivedEnv); statErr != nil {
		t.Fatal("file was touched despite the vault refusal")
	}
	if len(out.LeftAlone) != 1 || !strings.Contains(out.LeftAlone[0].Reason, "aren't all in the vault") {
		t.Fatalf("left-alone = %+v", out.LeftAlone)
	}

	// Vault the value: the same plan now deletes, backs up first, and the
	// undo index carries the Cleaned marker.
	if err := v.Set("proj/OPENAI_API_KEY", []byte(cleanTestSecret)); err != nil {
		t.Fatal(err)
	}
	out, err = ApplyClean(v, plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 1 || out.Deleted[0].Path != archivedEnv {
		t.Fatalf("deleted = %+v", out.Deleted)
	}
	if _, statErr := os.Stat(archivedEnv); !os.IsNotExist(statErr) {
		t.Error("file still exists after a reported deletion")
	}
	data, err := v.Get(out.Deleted[0].BackupPath)
	if err != nil || !strings.Contains(string(data), cleanTestSecret) {
		t.Errorf("backup unreadable or wrong: %v %q", err, data)
	}
	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, r := range recs {
		if r.OriginalPath == archivedEnv && r.Cleaned {
			marked = true
		}
	}
	if !marked {
		t.Error("no Cleaned-marked undo record for the deleted file")
	}
}

func TestApplyCleanTrashNeedsNoVaultMatch(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)

	out, err := ApplyClean(newTestVault(t), plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 1 {
		t.Fatalf("outcome %+v, want the trash file deleted with an empty vault", out)
	}
	if _, statErr := os.Stat(trashEnv); !os.IsNotExist(statErr) {
		t.Error("trash file still exists")
	}
}

func TestApplyCleanRunValuesCount(t *testing.T) {
	home := t.TempDir()
	archivedEnv := filepath.Join(home, "backup", ".env")
	writeFile(t, archivedEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, archivedEnv), nil)

	// Empty vault, but the value was vaulted by THIS run's migrate phase.
	out, err := ApplyClean(newTestVault(t), plan,
		[]AgentCacheSecret{{Value: cleanTestSecret, Var: "OPENAI_API_KEY"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 1 {
		t.Fatalf("outcome %+v, want same-run vaulted value to count", out)
	}
}

func TestApplyCleanRehashesBeforeUnlink(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)

	// The user (or anything else) edits the file after consent: the plan's
	// hash no longer holds, so the consent no longer covers it.
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\nNEW_NOTE=kept\n")

	out, err := ApplyClean(newTestVault(t), plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 0 {
		t.Fatal("deleted a file that changed since the plan")
	}
	if len(out.LeftAlone) != 1 || !strings.Contains(out.LeftAlone[0].Reason, "changed since the plan") {
		t.Fatalf("left-alone = %+v", out.LeftAlone)
	}
	if _, statErr := os.Stat(trashEnv); statErr != nil {
		t.Error("the changed file must survive")
	}
}

func TestApplyCleanSweptFileLeftAlone(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)

	out, err := ApplyClean(newTestVault(t), plan, nil, map[string]bool{trashEnv: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 0 {
		t.Fatal("deleted a file the cache sweep already redacted this run")
	}
	if len(out.LeftAlone) != 1 || !strings.Contains(out.LeftAlone[0].Reason, "already redacted") {
		t.Fatalf("left-alone = %+v", out.LeftAlone)
	}
}

func TestApplyCleanUndoRestores(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", ".env")
	content := "OPENAI_API_KEY=" + cleanTestSecret + "\n"
	writeFile(t, trashEnv, content)
	if err := os.Chmod(trashEnv, 0o644); err != nil {
		t.Fatal(err)
	}
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)
	v := newTestVault(t)
	out, err := ApplyClean(v, plan, nil, nil, nil)
	if err != nil || len(out.Deleted) != 1 {
		t.Fatalf("apply: %v %+v", err, out)
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var rec BackupRecord
	for _, r := range LatestBackups(recs) {
		if r.OriginalPath == trashEnv {
			rec = r
		}
	}
	if rec.OriginalPath == "" {
		t.Fatal("no undo record for the deleted file")
	}
	if err := RestoreFromBackup(v, rec); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	got, err := os.ReadFile(trashEnv)
	if err != nil || string(got) != content {
		t.Errorf("restored content = %q, %v; want the original bytes", got, err)
	}
	if info, err := os.Stat(trashEnv); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("restored mode = %v, %v; want 0644 preserved", info.Mode().Perm(), err)
	}
}

// TestApplyCleanUndoRestoresAfterParentRemoved is the headline undo promise
// under the case that broke it: --clean deletes a file, then the user empties
// the Trash so the parent directory is gone too. undo must recreate the
// directory and restore the bytes, not fail ENOENT after taking a Touch ID
// (code review, 2026-09-10).
func TestApplyCleanUndoRestoresAfterParentRemoved(t *testing.T) {
	home := t.TempDir()
	trashDir := filepath.Join(home, ".Trash", "old-proj")
	trashEnv := filepath.Join(trashDir, ".env")
	content := "OPENAI_API_KEY=" + cleanTestSecret + "\n"
	writeFile(t, trashEnv, content)
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)
	v := newTestVault(t)
	out, err := ApplyClean(v, plan, nil, nil, nil)
	if err != nil || len(out.Deleted) != 1 {
		t.Fatalf("apply: %v %+v", err, out)
	}

	// The user empties the Trash: the whole directory the file lived in is
	// gone, not just the file.
	if err := os.RemoveAll(trashDir); err != nil {
		t.Fatal(err)
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var rec BackupRecord
	for _, r := range LatestBackups(recs) {
		if r.OriginalPath == trashEnv {
			rec = r
		}
	}
	if rec.OriginalPath == "" {
		t.Fatal("no undo record for the deleted file")
	}
	if err := RestoreFromBackup(v, rec); err != nil {
		t.Fatalf("RestoreFromBackup with a vanished parent: %v", err)
	}
	got, err := os.ReadFile(trashEnv)
	if err != nil || string(got) != content {
		t.Errorf("restored content = %q, %v; want the original bytes", got, err)
	}
	// The recreated parent holds a plaintext secret and must not be world- or
	// group-accessible.
	if info, err := os.Stat(trashDir); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Errorf("recreated parent mode = %v, %v; want no group/other access", info.Mode().Perm(), err)
	}
}

// TestApplyCleanRefusesLiveSweptFile: a file an agent session was writing
// this run (SkipLive) must be refused by the delete pass, not unlinked out
// from under the live writer — design/migrate-clean.md D2, unenforced until
// the 2026-09-10 review.
func TestApplyCleanRefusesLiveSweptFile(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)

	out, err := ApplyClean(newTestVault(t), plan, nil, nil, map[string]bool{trashEnv: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 0 {
		t.Fatal("deleted a file an agent session was still writing")
	}
	if len(out.LeftAlone) != 1 || !strings.Contains(out.LeftAlone[0].Reason, "agent session was writing") {
		t.Fatalf("left-alone = %+v", out.LeftAlone)
	}
	if _, statErr := os.Stat(trashEnv); statErr != nil {
		t.Error("the refused file must still exist")
	}
}

// TestApplyCleanOutcomeDoesNotEchoPlanRefusals: a plan-time refusal is
// printed with the plan; ApplyClean's outcome must not carry it too, or the
// same refusal renders twice (code review, 2026-09-10).
func TestApplyCleanOutcomeDoesNotEchoPlanRefusals(t *testing.T) {
	home := t.TempDir()
	// An archived copy whose secret is NOT in the vault: PlanClean makes it a
	// candidate, ApplyClean refuses it at the vault check — that refusal is an
	// outcome row, correctly. Separately, a plan-time LeftAlone must not
	// reappear.
	trashEnv := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)
	plan.LeftAlone = append(plan.LeftAlone, CleanSkip{Path: filepath.Join(home, "x"), Reason: "a plan-time refusal"})

	out, err := ApplyClean(newTestVault(t), plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range out.LeftAlone {
		if s.Reason == "a plan-time refusal" {
			t.Error("ApplyClean echoed a plan-time refusal into its outcome; it prints twice")
		}
	}
}

func TestApplyCleanHardLinkRefused(t *testing.T) {
	home := t.TempDir()
	trashEnv := filepath.Join(home, ".Trash", ".env")
	writeFile(t, trashEnv, "OPENAI_API_KEY="+cleanTestSecret+"\n")
	plan := PlanClean(home, cleanScan(t, home, trashEnv), nil)
	if err := os.Link(trashEnv, filepath.Join(home, "other-name")); err != nil {
		t.Fatal(err)
	}

	out, err := ApplyClean(newTestVault(t), plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Deleted) != 0 {
		t.Fatal("unlinked a multiply-linked file; the content survives elsewhere")
	}
	if len(out.LeftAlone) != 1 || !strings.Contains(out.LeftAlone[0].Reason, "hard-linked") {
		t.Fatalf("left-alone = %+v", out.LeftAlone)
	}
}
