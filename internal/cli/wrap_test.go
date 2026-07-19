// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/wrap"
)

func execWrap(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	// Package-level flag vars persist across Execute calls in one test
	// binary (cobra re-parses into the same variable), so an --env from a
	// previous test would leak into a call that passes none.
	wrapAddEnv = nil
	wrapAddGrant = ""
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{"wrap"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

func TestWrapAddListUndoRoundTrip(t *testing.T) {
	home := withFixtureHome(t)

	out, err := execWrap(t, "add", "faketool", "--env", "FAKE_TOKEN=wrap-faketool/FAKE_TOKEN")
	if err != nil {
		t.Fatalf("jit wrap add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Wrapped faketool") {
		t.Errorf("expected a wrapped summary, got:\n%s", out)
	}

	link := filepath.Join(wrap.ShimDir(home), "faketool")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("shim not installed at %s: %v", link, err)
	}
	profilePath := filepath.Join(home, ".jit", "profiles", "wrap-faketool.yaml")
	if _, err := os.Stat(profilePath); err != nil {
		t.Errorf("profile not written at %s: %v", profilePath, err)
	}
	rc := wrap.RcFile(home, os.Getenv("SHELL"))
	if data, err := os.ReadFile(rc); err != nil || !strings.Contains(string(data), ".jit/shims") {
		t.Errorf("PATH line not ensured in %s (err=%v):\n%s", rc, err, data)
	}

	out, err = execWrap(t, "list")
	if err != nil {
		t.Fatalf("jit wrap list: %v", err)
	}
	if !strings.Contains(out, "faketool") || !strings.Contains(out, "env") || !strings.Contains(out, "FAKE_TOKEN") || !strings.Contains(out, "ok") {
		t.Errorf("list missing the wrapped tool row:\n%s", out)
	}

	out, err = execWrap(t, "undo", "faketool")
	if err != nil {
		t.Fatalf("jit wrap undo: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Unwrapped faketool") {
		t.Errorf("expected an unwrapped summary, got:\n%s", out)
	}
	if !strings.Contains(out, "wrap-faketool/FAKE_TOKEN") {
		t.Errorf("expected the kept vault path named, got:\n%s", out)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("shim survived undo: %v", err)
	}
	// Last tool gone -> the PATH line is cleaned up too.
	if data, _ := os.ReadFile(rc); strings.Contains(string(data), ".jit/shims") {
		t.Errorf("PATH line survived the last undo:\n%s", data)
	}
}

func TestWrapAddRequiresEnv(t *testing.T) {
	withFixtureHome(t)
	if _, err := execWrap(t, "add", "faketool"); err == nil {
		t.Fatal("expected jit wrap add without --env to fail")
	}
}

func TestWrapListEmpty(t *testing.T) {
	withFixtureHome(t)
	out, err := execWrap(t, "list")
	if err != nil {
		t.Fatalf("jit wrap list: %v", err)
	}
	if !strings.Contains(out, "No wrapped tools") {
		t.Errorf("expected the empty-state message, got:\n%s", out)
	}
}

func TestWrapUnknownToolListsCatalogAndEscapeHatch(t *testing.T) {
	withFixtureHome(t)
	_, err := execWrap(t, "sometool")
	if err == nil {
		t.Fatal("expected an error for an uncataloged tool")
	}
	if !strings.Contains(err.Error(), "gh") || !strings.Contains(err.Error(), "aws") {
		t.Errorf("error should list the catalog, got: %v", err)
	}
	if !strings.Contains(err.Error(), "jit wrap add sometool") {
		t.Errorf("error should point at the manual escape hatch, got: %v", err)
	}
}

func TestParseWrapEnv(t *testing.T) {
	env, order, err := parseWrapEnv([]string{"B=vault/b", "A=vault/a", "B=vault/b2"})
	if err != nil {
		t.Fatal(err)
	}
	if env["A"] != "vault/a" || env["B"] != "vault/b2" {
		t.Errorf("env = %v, want last-flag-wins for B", env)
	}
	if strings.Join(order, ",") != "B,A" {
		t.Errorf("order = %v, want first-appearance order [B A]", order)
	}
	for _, bad := range [][]string{nil, {"NOVALUE"}, {"=path"}, {"VAR="}} {
		if _, _, err := parseWrapEnv(bad); err == nil {
			t.Errorf("parseWrapEnv(%v): expected an error", bad)
		}
	}
}

// TestWrapAddGrantRoundTrip covers the grant-wrap path: `jit wrap add
// <tool> --grant <name>` installs a shim that grants a global mount (no
// profile), list shows it as a grant, doctor is happy, undo removes it.
func TestWrapAddGrantRoundTrip(t *testing.T) {
	withFixtureHome(t)

	out, err := execWrap(t, "add", "gcloud", "--grant", "gcp")
	if err != nil {
		t.Fatalf("jit wrap add --grant: %v", err)
	}
	if !strings.Contains(out, "Grant-wrapped gcloud") || !strings.Contains(out, "--with gcp") {
		t.Errorf("add --grant output missing the grant note:\n%s", out)
	}

	out, err = execWrap(t, "list")
	if err != nil {
		t.Fatalf("jit wrap list: %v", err)
	}
	if !strings.Contains(out, "gcloud") || !strings.Contains(out, "grant") || !strings.Contains(out, "--with gcp") {
		t.Errorf("list missing the grant-wrap row:\n%s", out)
	}

	// --env and --grant are mutually exclusive.
	if _, err := execWrap(t, "add", "x", "--env", "A=p", "--grant", "gcp"); err == nil {
		t.Error("expected an error when --env and --grant are combined")
	}

	if _, err := execWrap(t, "undo", "gcloud"); err != nil {
		t.Fatalf("jit wrap undo: %v", err)
	}
}
