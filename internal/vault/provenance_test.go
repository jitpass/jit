// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetWithMetaStampsAndRoundTrips is the happy path: provenance lands on a
// new secret, Info reads it back, and Get still decrypts (the new fields are
// bound into the v3 AAD, so a mismatch here would surface as a decrypt error).
func TestSetWithMetaStampsAndRoundTrips(t *testing.T) {
	v := newTestVault(t)
	want := []byte("sk_live_provenance")
	meta := Meta{Class: ClassDotenv, GroupID: "grp-abc", Origin: "~/scripts/jamf/.env"}

	if err := v.SetWithMeta("jamf/API_KEY", want, meta); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}
	got, err := v.Get("jamf/API_KEY")
	if err != nil {
		t.Fatalf("Get (v3 AAD round-trip): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Get = %q, want %q", got, want)
	}

	info, err := v.Info("jamf/API_KEY")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Version != envelopeVersion {
		t.Errorf("Version = %d, want %d", info.Version, envelopeVersion)
	}
	if info.Class != ClassDotenv || info.GroupID != "grp-abc" || info.Origin != "~/scripts/jamf/.env" {
		t.Errorf("provenance = {%q %q %q}, want {%q %q %q}", info.Class, info.GroupID, info.Origin, ClassDotenv, "grp-abc", "~/scripts/jamf/.env")
	}
	if info.OriginSeenUnix == 0 {
		t.Error("OriginSeenUnix = 0, want it stamped when Origin is present")
	}
}

// TestRotationPreservesProvenance is the birth-immutable rule: rotating a
// secret's value keeps its original class/group/origin even when the caller
// passes a different Meta, because a rotated value is the same secret from the
// same place. This is what lets `jit vault set` (which passes ClassManual)
// edit a migrated dotenv secret without relabeling it manual.
func TestRotationPreservesProvenance(t *testing.T) {
	v := newTestVault(t)
	birth := Meta{Class: ClassDotenv, GroupID: "grp-original", Origin: "~/a/.env"}
	if err := v.SetWithMeta("app/TOKEN", []byte("v1"), birth); err != nil {
		t.Fatalf("SetWithMeta (birth): %v", err)
	}

	// Rotate with deliberately conflicting provenance — it must be ignored.
	if err := v.SetWithMeta("app/TOKEN", []byte("v2"), Meta{Class: ClassManual, GroupID: "grp-new", Origin: "~/elsewhere"}); err != nil {
		t.Fatalf("SetWithMeta (rotation): %v", err)
	}

	got, err := v.Get("app/TOKEN")
	if err != nil {
		t.Fatalf("Get after rotation: %v", err)
	}
	if string(got) != "v2" {
		t.Errorf("value = %q, want the rotated %q", got, "v2")
	}
	info, _ := v.Info("app/TOKEN")
	if info.Class != ClassDotenv || info.GroupID != "grp-original" || info.Origin != "~/a/.env" {
		t.Errorf("rotation changed provenance to {%q %q %q}, want the birth {%q %q %q}", info.Class, info.GroupID, info.Origin, ClassDotenv, "grp-original", "~/a/.env")
	}
}

// TestBareSetHasNoProvenance: the provenance-agnostic entry point leaves the
// fields empty, exactly like a pre-provenance file, and still round-trips.
func TestBareSetHasNoProvenance(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("plain/KEY", []byte("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := v.Get("plain/KEY"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	info, _ := v.Info("plain/KEY")
	if info.Class != "" || info.GroupID != "" || info.Origin != "" || info.OriginSeenUnix != 0 {
		t.Errorf("bare Set left provenance {%q %q %q %d}, want all empty", info.Class, info.GroupID, info.Origin, info.OriginSeenUnix)
	}
}

// TestProvenanceIsAADBound: the class/group/origin are plaintext on disk but
// bound into the AAD, so hand-editing any of them makes Get fail closed rather
// than silently rewriting a secret's recorded origin.
func TestProvenanceIsAADBound(t *testing.T) {
	for _, field := range []string{"class", "group_id", "origin"} {
		t.Run(field, func(t *testing.T) {
			v := newTestVault(t)
			meta := Meta{Class: ClassMCP, GroupID: "grp-x", Origin: "~/.mcp.json"}
			if err := v.SetWithMeta("mcp/TOKEN", []byte("secret"), meta); err != nil {
				t.Fatalf("SetWithMeta: %v", err)
			}

			file := filepath.Join(v.vaultDir(), "mcp", "TOKEN.enc")
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("reading envelope: %v", err)
			}
			var env envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			switch field {
			case "class":
				env.Class = ClassManual
			case "group_id":
				env.GroupID = "grp-tampered"
			case "origin":
				env.Origin = "~/attacker/.mcp.json"
			}
			edited, _ := json.Marshal(env)
			if err := os.WriteFile(file, edited, 0o600); err != nil {
				t.Fatalf("writing tampered envelope: %v", err)
			}

			if _, err := v.Get("mcp/TOKEN"); err == nil {
				t.Fatalf("Get succeeded after tampering with %q, want a decrypt failure (AAD mismatch)", field)
			} else if !strings.Contains(err.Error(), "decrypting") {
				t.Errorf("Get error = %v, want a decrypting/AAD failure", err)
			}
		})
	}
}
