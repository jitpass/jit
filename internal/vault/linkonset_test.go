// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"testing"
)

// TestLinkOnSetInterceptStoresReference is the dedupe seam end to end: a
// hook claiming a SetWithMeta write must produce a reference envelope
// carrying the MIGRATOR'S meta (class stays, storage alone marks
// linkedness), resolving through the RefResolver like any linked secret.
func TestLinkOnSetInterceptStoresReference(t *testing.T) {
	v := newTestVault(t)
	r := &fakeResolver{value: []byte("live-credential")}
	v.RefResolver = r
	v.LinkOnSet = func(path string, value []byte, meta Meta) (string, bool) {
		if string(value) == "plaintext-from-dotenv" {
			return testRef, true
		}
		return "", false
	}

	meta := Meta{Class: ClassDotenv, GroupID: "g1", Origin: "file:///home/x/.env"}
	if err := v.SetWithMeta("myapp/DB_PASSWORD", []byte("plaintext-from-dotenv"), meta); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}

	info, err := v.Info("myapp/DB_PASSWORD")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Storage != StorageOpRef {
		t.Errorf("Storage = %q, want %q (hook claimed the write)", info.Storage, StorageOpRef)
	}
	if info.Class != ClassDotenv {
		t.Errorf("Class = %q, want the migrator's %q, not the link's", info.Class, ClassDotenv)
	}

	got, err := v.Get("myapp/DB_PASSWORD")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "live-credential" {
		t.Errorf("Get = %q, want the resolver's value", got)
	}
	if len(r.asked) != 1 || r.asked[0] != testRef {
		t.Errorf("resolver asked %v, want exactly [%s]", r.asked, testRef)
	}
}

func TestLinkOnSetDecliningStoresLiteral(t *testing.T) {
	v := newTestVault(t)
	v.LinkOnSet = func(string, []byte, Meta) (string, bool) { return "", false }

	if err := v.SetWithMeta("myapp/PLAIN", []byte("no-match-value"), Meta{Class: ClassDotenv}); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}
	info, err := v.Info("myapp/PLAIN")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Storage != "" {
		t.Errorf("Storage = %q, want a literal envelope when the hook declines", info.Storage)
	}
	got, err := v.Get("myapp/PLAIN")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "no-match-value" {
		t.Errorf("Get = %q, want the literal value", got)
	}
}

// TestLinkOnSetFiresOnSetWithOriginalValue: the agent-cache sweep hunts
// copies of the REAL value, which was on disk regardless of where the
// vault now points — so an intercepted write must report the plaintext,
// exactly once, and never the op:// string.
func TestLinkOnSetFiresOnSetWithOriginalValue(t *testing.T) {
	v := newTestVault(t)
	v.LinkOnSet = func(string, []byte, Meta) (string, bool) { return testRef, true }
	var reported []string
	v.OnSet = func(path string, value []byte) {
		reported = append(reported, string(value))
	}

	if err := v.SetWithMeta("myapp/TOKEN", []byte("the-real-value"), Meta{}); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}
	if len(reported) != 1 || reported[0] != "the-real-value" {
		t.Errorf("OnSet saw %q, want exactly [the-real-value]", reported)
	}
}

func TestSetReferenceNeverFiresOnSetOrConsultsHook(t *testing.T) {
	v := newTestVault(t)
	v.LinkOnSet = func(string, []byte, Meta) (string, bool) {
		t.Error("LinkOnSet consulted by SetReference; the caller already chose the reference")
		return "", false
	}
	v.OnSet = func(path string, value []byte) {
		t.Errorf("OnSet fired for a reference write with %q; a reference is not a credential", value)
	}
	if err := v.SetReference("stripe/live", testRef, Meta{Class: ClassOnePassword}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
}

func TestLinkOnSetSkipsReservedNamespaces(t *testing.T) {
	v := newTestVault(t)
	v.LinkOnSet = func(path string, _ []byte, _ Meta) (string, bool) {
		t.Errorf("LinkOnSet consulted for reserved path %q; jit's own bookkeeping must never be diverted", path)
		return "", false
	}
	backup := BackupPathPrefix + "home/x/.env/1234567890"
	if err := v.SetWithMeta(backup, []byte("KEY=whole-file-backup-content\n"), Meta{}); err != nil {
		t.Fatalf("SetWithMeta backup: %v", err)
	}
	info, err := v.Info(backup)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Storage != "" {
		t.Errorf("backup Storage = %q, want literal", info.Storage)
	}
}
