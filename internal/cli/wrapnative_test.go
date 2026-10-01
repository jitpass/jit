// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/wrap"
)

// TestNativeWrapDelegationPlansTheCredential runs the command `jit wrap
// <native tool>` delegates to, as a dry run, against a home holding that
// tool's credential file. Until 2.3.8 the delegation named the home
// directory, which migrate walks for project files only, so every native
// wrap (and JitPass's Protect in Tools) answered "Nothing to migrate".
func TestNativeWrapDelegationPlansTheCredential(t *testing.T) {
	files := map[string]struct{ path, body, plan string }{
		"aws": {".aws/credentials",
			"[default]\naws_access_key_id = AKIAFIXTURE0123456789\naws_secret_access_key = FIXTUREsecretKey0123456789abcdefFIXTURE00\n", // gitleaks:allow
			"[AWS profile in ~/.aws/credentials] 1"},
		"docker": {".docker/config.json",
			`{"auths":{"registry.example.com":{"auth":"ZGFuYTpGSVhUVVJFcGFzc3dvcmQwMTIzNDU2Nzg5"}}}`, // gitleaks:allow
			"registry.example.com"},
		"git": {".config/git/credentials",
			"https://dana:FIXTUREgitToken0123456789abcdef@git.example.com\n", // gitleaks:allow
			"git.example.com"},
		"terraform": {".terraform.d/credentials.tfrc.json",
			`{"credentials":{"app.terraform.io":{"token":"FIXTURE.atlasv1.0123456789abcdefFIXTURE0123456789abcdef"}}}`, // gitleaks:allow
			"app.terraform.io"},
	}
	for tool, f := range files {
		t.Run(tool, func(t *testing.T) {
			home := withFixtureHome(t)
			withFixtureCwd(t)
			writeArtifact(t, home+"/"+f.path, f.body)
			entry, _ := wrap.Lookup(tool)
			d, err := wrap.Delegation(entry, migrate.NativeTargets(home, entry.NativeCategory))
			if err != nil {
				t.Fatal(err)
			}
			out, err := execMigrate(t, append(d.Command[1:], "--dry-run")...)
			if err != nil {
				t.Fatalf("jit %s --dry-run: %v\n%s", strings.Join(d.Command, " "), err, out)
			}
			if strings.Contains(out, "Nothing to migrate") || !strings.Contains(out, f.plan) {
				t.Errorf("jit %s planned nothing for %s; want %q in:\n%s", strings.Join(d.Command, " "), f.path, f.plan, out)
			}
		})
	}
}
