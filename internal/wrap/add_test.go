// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"os"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func addGH(t *testing.T, home string) AddResult {
	t.Helper()
	res, err := Add(home, AddRequest{
		Tool:      "gh",
		Env:       map[string]string{"GH_TOKEN": "wrap-gh/GH_TOKEN", "GH_HOST": "wrap-gh/GH_HOST"},
		Order:     []string{"GH_TOKEN", "GH_HOST"},
		JitBinary: "/usr/bin/true",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return res
}

func TestAddWritesProfileShimAndManifest(t *testing.T) {
	home := t.TempDir()
	res := addGH(t, home)

	if res.ProfileName != "wrap-gh" {
		t.Errorf("profile name %q, want wrap-gh", res.ProfileName)
	}
	p, order, err := profile.LoadFileOrdered(res.ProfilePath)
	if err != nil {
		t.Fatalf("profile unreadable: %v", err)
	}
	if p["GH_TOKEN"] != "wrap-gh/GH_TOKEN" || p["GH_HOST"] != "wrap-gh/GH_HOST" {
		t.Errorf("profile mapping mangled: %v", p)
	}
	if len(order) != 2 || order[0] != "GH_TOKEN" || order[1] != "GH_HOST" {
		t.Errorf("profile order = %v, want flag order [GH_TOKEN GH_HOST]", order)
	}
	if info, err := os.Stat(res.ProfilePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("profile file mode/err = %v/%v, want 0600/nil", info.Mode().Perm(), err)
	}

	if target, err := os.Readlink(res.ShimPath); err != nil || target != "/usr/bin/true" {
		t.Errorf("shim link (%q, %v), want /usr/bin/true", target, err)
	}

	m, err := LoadManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := m.Tools["gh"]
	if !ok {
		t.Fatalf("gh not recorded in manifest: %v", m.Tools)
	}
	if entry.Profile != "wrap-gh" || strings.Join(entry.Vars, ",") != "GH_TOKEN,GH_HOST" {
		t.Errorf("manifest entry mangled: %+v", entry)
	}
	if entry.AddedAt.IsZero() {
		t.Error("AddedAt not stamped")
	}
}

func TestAddIsIdempotentForManagedTool(t *testing.T) {
	home := t.TempDir()
	addGH(t, home)

	res, err := Add(home, AddRequest{
		Tool:      "gh",
		Env:       map[string]string{"GH_TOKEN": "elsewhere/GH_TOKEN"},
		Order:     []string{"GH_TOKEN"},
		JitBinary: "/usr/bin/false",
	})
	if err != nil {
		t.Fatalf("re-Add of a wrap-managed tool: %v", err)
	}
	p, err := profile.LoadFile(res.ProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	if p["GH_TOKEN"] != "elsewhere/GH_TOKEN" || len(p) != 1 {
		t.Errorf("re-Add didn't refresh the profile: %v", p)
	}
	if target, _ := os.Readlink(res.ShimPath); target != "/usr/bin/false" {
		t.Errorf("re-Add didn't refresh the shim target: %q", target)
	}
}

func TestAddRefusesForeignProfile(t *testing.T) {
	home := t.TempDir()
	path, err := profile.Path(home, "wrap-gh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(strings.TrimSuffix(path, "/wrap-gh.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("GH_TOKEN: hand/written\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Add(home, AddRequest{
		Tool:      "gh",
		Env:       map[string]string{"GH_TOKEN": "wrap-gh/GH_TOKEN"},
		Order:     []string{"GH_TOKEN"},
		JitBinary: "/usr/bin/true",
	})
	if err == nil {
		t.Fatal("expected Add to refuse overwriting a profile it doesn't manage")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "GH_TOKEN: hand/written\n" {
		t.Errorf("foreign profile was modified:\n%s", data)
	}
}

func TestAddValidatesInput(t *testing.T) {
	home := t.TempDir()
	base := AddRequest{JitBinary: "/usr/bin/true"}

	bad := []AddRequest{
		func(r AddRequest) AddRequest { r.Tool = "jit"; r.Env = map[string]string{"A": "b"}; return r }(base),
		func(r AddRequest) AddRequest { r.Tool = "gh"; return r }(base), // no env
		func(r AddRequest) AddRequest {
			r.Tool = "gh"
			r.Env = map[string]string{"2BAD": "b"}
			return r
		}(base),
		func(r AddRequest) AddRequest {
			r.Tool = "gh"
			r.Env = map[string]string{"GOOD": ""}
			return r
		}(base),
	}
	for i, req := range bad {
		if _, err := Add(home, req); err == nil {
			t.Errorf("case %d: expected a validation error for %+v", i, req)
		}
	}
}
