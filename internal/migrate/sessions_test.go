// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// assertSessionStamp checks that EVERY secret of a session profile carries
// the expiry as metadata — readable through Info, so without a prompt.
func assertSessionStamp(t *testing.T, v *vault.Vault, vaultProfile string, want int64) {
	t.Helper()
	for _, varName := range []string{"ACCESS_KEY_ID", "SECRET_ACCESS_KEY", "SESSION_TOKEN", "EXPIRATION"} {
		info, err := v.Info(vaultProfile + "/" + varName)
		if err != nil {
			t.Errorf("Info(%s/%s): %v", vaultProfile, varName, err)
			continue
		}
		if info.ExpiresUnix != want {
			t.Errorf("%s/%s ExpiresUnix = %d, want %d", vaultProfile, varName, info.ExpiresUnix, want)
		}
	}
}

func TestExpiryStamp(t *testing.T) {
	stamp := time.Date(2026, 7, 29, 19, 0, 11, 0, time.UTC).Unix()
	for in, want := range map[string]int64{
		"2026-07-29T19:00:11Z":      stamp,
		"2026-07-29T22:00:11+03:00": stamp, // same instant, as a zoned clock prints it
		"":                          0,
		"tomorrow-ish":              0,
	} {
		if got := expiryStamp(in); got != want {
			t.Errorf("expiryStamp(%q) = %d, want %d", in, got, want)
		}
	}
}

// A malformed stamp must still store and serve the value verbatim (the
// SDK's own complaint wins) — it just carries no metadata.
func TestStoreAWSSessionMalformedExpirationStampsNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	if _, err := StoreAWSSession(v, home, "prod", AWSSession{
		AccessKeyID: "ASIA1", SecretAccessKey: "secret1", SessionToken: "tok", Expiration: "soon",
	}); err != nil {
		t.Fatalf("StoreAWSSession: %v", err)
	}
	if got, err := v.Get("aws-prod/EXPIRATION"); err != nil || string(got) != "soon" {
		t.Errorf("EXPIRATION = (%q, %v), want it stored verbatim", got, err)
	}
	assertSessionStamp(t, v, "aws-prod", 0)
}

func TestListSessions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	// live: a capture from an hour ago, twelve hours long.
	if _, err := StoreAWSSession(v, home, "stage", AWSSession{
		AccessKeyID: "A", SecretAccessKey: "S", SessionToken: "T",
		Expiration: now.Add(11 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("StoreAWSSession stage: %v", err)
	}
	// expired: yesterday's.
	if _, err := StoreAWSSession(v, home, "prod", AWSSession{
		AccessKeyID: "A", SecretAccessKey: "S", SessionToken: "T",
		Expiration: now.Add(-3 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("StoreAWSSession prod: %v", err)
	}
	// stampless: a capture stored before the expiry metadata existed —
	// the manifest names EXPIRATION, the envelope carries no stamp.
	writeManifest(t, home, "aws-dev", "ACCESS_KEY_ID: aws-dev/ACCESS_KEY_ID\nEXPIRATION: aws-dev/EXPIRATION\n")
	for _, p := range []string{"aws-dev/ACCESS_KEY_ID", "aws-dev/EXPIRATION"} {
		if err := v.Set(p, []byte("x")); err != nil {
			t.Fatalf("Set %s: %v", p, err)
		}
	}
	// not a session: a static key with no EXPIRATION at all.
	writeManifest(t, home, "aws-ci", "ACCESS_KEY_ID: aws-ci/ACCESS_KEY_ID\nSECRET_ACCESS_KEY: aws-ci/SECRET_ACCESS_KEY\n")
	// half-present: manifest says EXPIRATION, vault has no such secret.
	writeManifest(t, home, "aws-gone", "EXPIRATION: aws-gone/EXPIRATION\n")
	// unreadable: a manifest that is not a map. jit status must survive
	// it, so the listing skips it rather than failing the whole call.
	writeManifest(t, home, "broken", "- not\n- a map\n")

	sessions, err := ListSessions(v, home, now)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("ListSessions returned %d sessions, want 3 (dev, prod, stage):\n%+v", len(sessions), sessions)
	}
	byName := map[string]Session{}
	for _, s := range sessions {
		byName[s.Profile] = s
	}
	if got := []string{sessions[0].Profile, sessions[1].Profile, sessions[2].Profile}; got[0] != "aws-dev" || got[1] != "aws-prod" || got[2] != "aws-stage" {
		t.Errorf("order = %v, want sorted by profile", got)
	}

	stage := byName["aws-stage"]
	if !stage.Live(now) || stage.Remaining(now) != 11*time.Hour {
		t.Errorf("stage: Live=%v Remaining=%s, want live with 11h", stage.Live(now), stage.Remaining(now))
	}
	if stage.Origin != "~/.clisso.yaml" {
		t.Errorf("stage.Origin = %q, want ~/.clisso.yaml (which tool minted it)", stage.Origin)
	}
	prod := byName["aws-prod"]
	if prod.Live(now) || prod.Remaining(now) != 0 {
		t.Errorf("prod: Live=%v Remaining=%s, want expired", prod.Live(now), prod.Remaining(now))
	}
	dev := byName["aws-dev"]
	if dev.ExpiresUnix != 0 || !dev.Live(now) {
		t.Errorf("dev (stampless): ExpiresUnix=%d Live=%v, want unknown and reported live, never expired", dev.ExpiresUnix, dev.Live(now))
	}
	if _, ok := byName["aws-ci"]; ok {
		t.Error("a static key with no EXPIRATION was listed as a session")
	}
	if _, ok := byName["aws-gone"]; ok {
		t.Error("a manifest whose EXPIRATION secret is missing was listed as a session")
	}
	if _, ok := byName["broken"]; ok {
		t.Error("an unparsable manifest was listed as a session")
	}
}

func writeManifest(t *testing.T, home, name, body string) {
	t.Helper()
	dir := filepath.Join(home, profile.ProfilesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
