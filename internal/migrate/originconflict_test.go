// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

func TestInspectOriginConflictFiresOnADifferentSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	// The real case: a static IAM key migrated out of ~/.aws/credentials,
	// then a clisso app that happens to share the profile name.
	writeAWSFixture(t, home, "[prod]\naws_access_key_id = AKIASTATIC\naws_secret_access_key = staticsecret\n", "")
	if _, err := ApplyAWSProfile(v, home, "prod"); err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}
	c := InspectOriginConflict(v, "aws-prod/SECRET_ACCESS_KEY", vault.ClassAWS, ClissoConfigPath(home))
	if c == nil {
		t.Fatal("expected a conflict: the stored key came from ~/.aws/credentials, the capture comes from clisso")
	}
	if !strings.Contains(c.Describe(), ".aws/credentials") {
		t.Errorf("Describe() = %q, want it to name where the stored secret came from", c.Describe())
	}
}

func TestInspectOriginConflictQuietOnRotation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	// Capture, then capture again — same source, so this is a rotation and
	// must not warn. A guard that cries on every login is a guard nobody
	// reads.
	if _, err := StoreAWSSession(v, home, "prod", AWSSession{
		AccessKeyID: "ASIA1", SecretAccessKey: "secret1", SessionToken: "tok1", Expiration: "2099-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("StoreAWSSession: %v", err)
	}
	if c := InspectOriginConflict(v, "aws-prod/SECRET_ACCESS_KEY", vault.ClassAWS, ClissoConfigPath(home)); c != nil {
		t.Errorf("rotation must not warn, got %+v", c)
	}

	// And re-migrating a file-sourced profile is equally a rotation.
	writeAWSFixture(t, home, "[other]\naws_access_key_id = AKIA1\naws_secret_access_key = s1\n", "")
	if _, err := ApplyAWSProfile(v, home, "other"); err != nil {
		t.Fatalf("ApplyAWSProfile: %v", err)
	}
	if c := InspectOriginConflict(v, "aws-other/SECRET_ACCESS_KEY", vault.ClassAWS, AWSCredentialsPath(home)); c != nil {
		t.Errorf("re-migrating the same file must not warn, got %+v", c)
	}
}

func TestInspectOriginConflictClassChange(t *testing.T) {
	// The wrap case: a token stored by hand (ClassManual), then
	// `jit wrap <tool>` finds one on disk and replaces it.
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	if err := v.SetWithMeta("wrap-openai/OPENAI_API_KEY", []byte("sk-handstored"), vault.Meta{Class: vault.ClassManual}); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}
	c := InspectOriginConflict(v, "wrap-openai/OPENAI_API_KEY", vault.ClassWrap, "~/.config/openai/config")
	if c == nil {
		t.Fatal("expected a conflict: hand-stored secret about to be replaced by a discovered one")
	}
	if !strings.Contains(c.Describe(), "by hand") {
		t.Errorf("Describe() = %q, want it to say the secret was stored by hand", c.Describe())
	}
}

func TestInspectOriginConflictUnknownPathIsQuiet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	if c := InspectOriginConflict(v, "aws-nothing/SECRET_ACCESS_KEY", vault.ClassAWS, ClissoConfigPath(home)); c != nil {
		t.Errorf("nothing stored yet must not warn, got %+v", c)
	}
}

func TestStoreAWSSessionRecordsAStableOrigin(t *testing.T) {
	// normalizeOrigin turns any non-empty string into a PATH, so a bare
	// label like "clisso" would be stored as <cwd>/clisso — different for
	// every directory the user runs `clisso get` from.
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	if _, err := StoreAWSSession(v, home, "prod", AWSSession{
		AccessKeyID: "ASIA1", SecretAccessKey: "secret1",
	}); err != nil {
		t.Fatalf("StoreAWSSession: %v", err)
	}
	info, err := v.Info("aws-prod/SECRET_ACCESS_KEY")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !strings.HasSuffix(info.Origin, ".clisso.yaml") {
		t.Errorf("Origin = %q, want clisso's config (a real, stable path)", info.Origin)
	}
	if info.Class != vault.ClassAWS {
		t.Errorf("Class = %q, want %q — internal/consent gates on that exact string", info.Class, vault.ClassAWS)
	}
}

func TestReplacingNoteKeepsTheCommandWhole(t *testing.T) {
	// The prose is one unbroken line for the cli layer to wrap at the real
	// terminal width; the recovery command comes back separately so it can
	// have its own line. Wrapping breaks on spaces, and a `jit vault
	// history …` folded mid-phrase is one the reader has to reassemble
	// before they can run it.
	c := OriginConflict{Path: "aws-prod/SECRET_ACCESS_KEY", Origin: "~/.aws/credentials"}
	prose, command := c.ReplacingNote()

	if strings.Contains(prose, "\n") {
		t.Errorf("prose must be one unwrapped line, got:\n%s", prose)
	}
	if strings.Contains(prose, "jit vault history") {
		t.Errorf("the command must not be inside the wrappable prose, got:\n%s", prose)
	}
	if command != "`jit vault history aws-prod/SECRET_ACCESS_KEY`" {
		t.Errorf("command = %q, want the backticked recovery command (hlCmds strips the backticks)", command)
	}
	if !strings.Contains(prose, "aws-prod/SECRET_ACCESS_KEY") || !strings.Contains(prose, "~/.aws/credentials") {
		t.Errorf("prose must name both the path and where the old value came from, got:\n%s", prose)
	}
}
