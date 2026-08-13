// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/vault"
)

func dupTestGroup(name, origin string, originExists bool, profiles []string, kv map[string]string) *dupGroup {
	g := &dupGroup{name: name, origin: origin, originExists: originExists, profiles: profiles, hashes: map[string]string{}}
	for k, v := range kv {
		g.keys = append(g.keys, k)
		g.hashes[k] = "h:" + v // any injective mapping stands in for the digest
	}
	sort.Strings(g.keys)
	return g
}

// TestSameFileFindings pins the same-file verdicts: a copied tree's two
// migrations pair on (key set, origin tail) and matching values, the
// removal pick prefers a gone origin then an unreferenced group then the
// later name, the remedy routes to `jit migrate remove` only while the
// origin file exists, and diverged values get no removal pick at all.
func TestSameFileFindings(t *testing.T) {
	// Copied workspace: both live and wired -> pick the later name, route
	// to migrate remove of ITS origin.
	groups := map[string]*dupGroup{
		"mcp-caido":   dupTestGroup("mcp-caido", "/u/Documents/ws/.mcp.json", true, []string{"mcp-caido"}, map[string]string{"CAIDO_URL": "v1"}),
		"mcp-caido-2": dupTestGroup("mcp-caido-2", "/u/Desktop/ws/.mcp.json", true, []string{"mcp-caido-2"}, map[string]string{"CAIDO_URL": "v1"}),
	}
	fs := sameFileFindings(groups)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %+v", fs)
	}
	f := fs[0]
	if f.SameOrigin || !f.ValuesMatch {
		t.Errorf("copied-tree finding flags = %+v", f)
	}
	if f.RemoveGroup != "mcp-caido-2" || f.RemoveCommand != "jit migrate remove /u/Desktop/ws/.mcp.json" {
		t.Errorf("removal pick = %q / %q, want the later name via migrate remove", f.RemoveGroup, f.RemoveCommand)
	}

	if f.Prunable {
		t.Errorf("a copy whose file still exists must never be prunable: %+v", f)
	}

	// A copy whose origin is gone and which nothing references is the pick,
	// and is the ONE shape --prune may delete itself.
	groups["mcp-caido-2"] = dupTestGroup("mcp-caido-2", "/u/Desktop/ws/.mcp.json", false, nil, map[string]string{"CAIDO_URL": "v1"})
	fs = sameFileFindings(groups)
	if len(fs) != 1 || fs[0].RemoveGroup != "mcp-caido-2" || fs[0].RemoveCommand != "jit vault duplicates --prune" {
		t.Errorf("gone-origin pick = %+v, want mcp-caido-2 via duplicates --prune", fs)
	}
	if !fs[0].Prunable || strings.Join(fs[0].RemovePaths, ",") != "mcp-caido-2/CAIDO_URL" {
		t.Errorf("gone-origin unreferenced finding must be prunable with its paths, got %+v", fs[0])
	}

	// Gone origin but still wired somewhere -> vault rm of the exact paths,
	// and NOT prunable: deleting them would leave that manifest pointing at
	// holes, which is a per-path decision.
	groups["mcp-caido-2"] = dupTestGroup("mcp-caido-2", "/u/Desktop/ws/.mcp.json", false, []string{"mcp-caido-2"}, map[string]string{"CAIDO_URL": "v1"})
	fs = sameFileFindings(groups)
	if len(fs) != 1 || fs[0].RemoveCommand != "jit vault rm mcp-caido-2/CAIDO_URL" {
		t.Errorf("gone-origin wired pick = %+v, want vault rm of the group's paths", fs)
	}
	if fs[0].Prunable {
		t.Errorf("a still-referenced copy must never be prunable: %+v", fs[0])
	}

	// Diverged values -> reported, but no removal pick: which copy is right
	// is the user's call.
	groups["mcp-caido-2"] = dupTestGroup("mcp-caido-2", "/u/Desktop/ws/.mcp.json", true, []string{"mcp-caido-2"}, map[string]string{"CAIDO_URL": "v2"})
	fs = sameFileFindings(groups)
	if len(fs) != 1 || fs[0].ValuesMatch || fs[0].RemoveCommand != "" || fs[0].RemoveGroup != "" {
		t.Errorf("diverged finding = %+v, want values_match=false and no removal pick", fs)
	}

	// Same key set from UNRELATED files (different tails) is not a
	// same-file finding at all — that shape belongs to shared credentials.
	groups = map[string]*dupGroup{
		"export-a": dupTestGroup("export-a", "/u/scripts/inventory/.env", true, []string{"export-a"}, map[string]string{"JAMF_CLIENT_ID": "v1"}),
		"export-b": dupTestGroup("export-b", "/u/scripts/computers/.env", true, []string{"export-b"}, map[string]string{"JAMF_CLIENT_ID": "v1"}),
	}
	if fs = sameFileFindings(groups); len(fs) != 0 {
		t.Errorf("unrelated files must not pair as same-file, got %+v", fs)
	}

	// A re-migration fork: literally the same origin twice.
	groups = map[string]*dupGroup{
		"wiz":   dupTestGroup("wiz", "/u/scripts/.env", true, []string{"wiz"}, map[string]string{"A": "v1", "B": "v2"}),
		"wiz-2": dupTestGroup("wiz-2", "/u/scripts/.env", true, nil, map[string]string{"A": "v1", "B": "v2"}),
	}
	fs = sameFileFindings(groups)
	if len(fs) != 1 || !fs[0].SameOrigin || fs[0].RemoveGroup != "wiz-2" {
		t.Errorf("same-origin fork = %+v, want SameOrigin with the unreferenced copy picked", fs)
	}
}

// TestSharedCredentialFindings pins the shared-credential verdict: the same
// value under the same key across independent groups clusters into ONE
// finding per group set, config-named keys never count, and groups already
// consumed by a same-file finding stay out.
func TestSharedCredentialFindings(t *testing.T) {
	jamfCreds := map[string]string{"JAMF_CLIENT_ID": "id", "JAMF_CLIENT_SECRET": "sec", "OUTPUT_FILE": "same-path"}
	groups := map[string]*dupGroup{
		"jamf":     dupTestGroup("jamf", "/u/a/.env", true, []string{"jamf"}, jamfCreds),
		"jamf-2":   dupTestGroup("jamf-2", "/u/b/.env", true, []string{"jamf-2"}, jamfCreds),
		"export-c": dupTestGroup("export-c", "/u/c/.env", true, []string{"export-c"}, jamfCreds),
		"other":    dupTestGroup("other", "/u/d/.env", true, []string{"other"}, map[string]string{"API_KEY": "unrelated"}),
	}
	fs := sharedCredentialFindings(groups, nil)
	if len(fs) != 1 {
		t.Fatalf("want one merged finding, got %+v", fs)
	}
	if strings.Join(fs[0].Groups, ",") != "export-c,jamf,jamf-2" {
		t.Errorf("groups = %v", fs[0].Groups)
	}
	// The two credential keys merge into one finding; OUTPUT_FILE (config
	// by name) must not appear even though its value is shared too.
	if strings.Join(fs[0].Keys, ",") != "JAMF_CLIENT_ID,JAMF_CLIENT_SECRET" {
		t.Errorf("keys = %v, config-named keys must not count", fs[0].Keys)
	}

	// Groups consumed by a same-file finding don't re-report as shared.
	consumed := []dupFinding{{Groups: []string{"jamf", "jamf-2"}}}
	fs = sharedCredentialFindings(groups, consumed)
	for _, f := range fs {
		for _, g := range f.Groups {
			if g == "jamf" || g == "jamf-2" {
				t.Errorf("consumed group %s re-reported as shared: %+v", g, fs)
			}
		}
	}
}

// TestPrintDuplicatesReport pins the text shapes: the findings section with
// its evidence and remedy lines, the shared-credentials keep-all section,
// the diverged caveat, and the empty state.
func TestPrintDuplicatesReport(t *testing.T) {
	var buf bytes.Buffer
	printDuplicatesReport(&buf, []dupFinding{{
		Groups: []string{"mcp-caido", "mcp-caido-2"}, Keys: []string{"CAIDO_URL"},
		Origins:     []string{"/u/Documents/ws/.mcp.json", "/u/Desktop/ws/.mcp.json"},
		ValuesMatch: true, RemoveGroup: "mcp-caido-2",
		RemoveCommand: "jit migrate remove /u/Desktop/ws/.mcp.json",
	}}, []sharedFinding{{
		Keys: []string{"JAMF_CLIENT_ID"}, Groups: []string{"jamf", "jamf-2"},
	}}, 118)
	out := buf.String()
	for _, want := range []string{
		"[duplicates] 1 finding across 118 stored secrets",
		"mcp-caido, mcp-caido-2: one file, migrated from two copies",
		"1 shared key (CAIDO_URL), identical values",
		"from /u/Documents/ws/.mcp.json",
		"mcp-caido-2 looks stale, retire it with:",
		"jit migrate remove /u/Desktop/ws/.mcp.json",
		"[shared credentials] 1 · same value in independent tools, keep all",
		"JAMF_CLIENT_ID",
		"shared by 2 profiles",
		"removing any copy breaks its tool; when rotating, update every copy",
		"118 secrets compared in memory; no value was printed or written.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "vault rm") {
		t.Errorf("a live-mounted copy must route to migrate remove, never rm, got:\n%s", out)
	}

	// Diverged: caveat instead of a remedy.
	buf.Reset()
	printDuplicatesReport(&buf, []dupFinding{{
		Groups: []string{"a", "a-2"}, Keys: []string{"K"},
		Origins: []string{"/u/x/.env", "/u/y/.env"},
	}}, nil, 4)
	if !strings.Contains(buf.String(), "copies that have diverged") ||
		!strings.Contains(buf.String(), "compare the files before retiring either") {
		t.Errorf("diverged report wrong, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "retire it with") {
		t.Errorf("diverged copies must get no removal pick, got:\n%s", buf.String())
	}

	// Empty state.
	buf.Reset()
	printDuplicatesReport(&buf, nil, nil, 42)
	if !strings.Contains(buf.String(), "No duplicates") || !strings.Contains(buf.String(), "42 secrets compared") {
		t.Errorf("empty state wrong, got:\n%s", buf.String())
	}
}

// TestGatherDupGroupsExpandsTildeOrigins pins the form real migrations
// write. Origin is stored ALREADY tilde-shortened ("~/proj/.env"), so
// statting it raw always failed and originExists was permanently false:
// the `jit migrate remove` remedy became dead code and every live
// duplicate was routed to `jit vault rm`, the precise advice this command
// exists to stop giving. The earlier tests missed it by supplying absolute
// origins no migration ever records.
func TestGatherDupGroupsExpandsTildeOrigins(t *testing.T) {
	home := withFixtureHome(t)
	cwd := t.TempDir()
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}

	// A real file under the fixture home, recorded the way migrate records
	// it: relative to home, with a leading "~/".
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	livePath := filepath.Join(home, "proj", ".env")
	if err := os.WriteFile(livePath, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.SetWithMeta("live/A", []byte("secret-value"),
		vault.Meta{Class: vault.ClassDotenv, Origin: "~/proj/.env"}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetWithMeta("gone/A", []byte("secret-value"),
		vault.Meta{Class: vault.ClassDotenv, Origin: "~/deleted/.env"}); err != nil {
		t.Fatal(err)
	}

	groups, _, err := gatherDupGroups(v, root, cwd, []string{"live/A", "gone/A"})
	if err != nil {
		t.Fatalf("gatherDupGroups: %v", err)
	}
	if g := groups["live"]; g == nil || !g.originExists {
		t.Errorf("a tilde origin whose file EXISTS must stat true, got %+v", g)
	}
	if g := groups["gone"]; g == nil || g.originExists {
		t.Errorf("a tilde origin whose file is gone must stat false, got %+v", g)
	}

	// End to end: the live copy must be routed to migrate remove, never rm.
	groups["live"].keys = []string{"A"}
	groups["gone"].keys = []string{"A"}
	groups["gone"].origin = "~/proj/.env" // same tail, so they cluster
	groups["gone"].originExists = false
	fs := sameFileFindings(groups)
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %+v", fs)
	}
	if fs[0].RemoveGroup != "gone" {
		t.Errorf("the copy whose file is gone must be the pick, got %+v", fs[0])
	}
	// And with the live one picked instead, the remedy must be migrate remove.
	groups["gone"].originExists = true
	fs = sameFileFindings(groups)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].RemoveCommand, "jit migrate remove ") {
		t.Errorf("a copy whose file exists must route to migrate remove, got %+v", fs)
	}
}

// TestSameFileFindingsUsesProfileSourceForPreProvenance is the miss that
// made v0.92.0 useless on the vault it was built for. A pre-provenance
// (v1/v2) envelope carries NO Origin, so keying on Origin alone skipped the
// older copy entirely, its newer twin had nothing to pair with, and both
// landed in "shared credentials, keep all" — the report calling a real
// duplicate a credential to keep. The referencing profile's recorded source
// is the evidence that does exist for those secrets, and is what
// `jit vault get`'s own "migrated from" footer has always shown.
func TestSameFileFindingsUsesProfileSourceForPreProvenance(t *testing.T) {
	// The older copy: no Origin at all, only a profile-recorded source.
	old := dupTestGroup("mcp-caido", "", true, []string{"mcp-caido"}, map[string]string{"CAIDO_URL": "v1"})
	old.ownerConfig = "~/Documents/ai_security_workspace/.mcp.json"
	// The newer twin, migrated after provenance shipped.
	newer := dupTestGroup("mcp-caido-2", "~/Desktop/Share/ai_security_workspace/.mcp.json",
		true, []string{"mcp-caido-2"}, map[string]string{"CAIDO_URL": "v1"})

	groups := map[string]*dupGroup{"mcp-caido": old, "mcp-caido-2": newer}
	fs := sameFileFindings(groups)
	if len(fs) != 1 {
		t.Fatalf("a pre-provenance copy must still pair with its twin, got %+v", fs)
	}
	if strings.Join(fs[0].Groups, ",") != "mcp-caido,mcp-caido-2" {
		t.Errorf("groups = %v", fs[0].Groups)
	}
	// Its origin column must show the profile-recorded source, not blank.
	if fs[0].Origins[0] != "~/Documents/ai_security_workspace/.mcp.json" {
		t.Errorf("origins = %v, want the profile source for the pre-provenance copy", fs[0].Origins)
	}
	if !fs[0].ValuesMatch {
		t.Errorf("identical values must still compare equal, got %+v", fs[0])
	}

	// And it must be excluded from the shared-credentials bucket, which is
	// where it wrongly showed up before.
	shared := sharedCredentialFindings(groups, fs)
	for _, f := range shared {
		for _, g := range f.Groups {
			if g == "mcp-caido" || g == "mcp-caido-2" {
				t.Errorf("a paired duplicate must not also read as a shared credential: %+v", shared)
			}
		}
	}
}

// TestSameFileFindingsCopiedThenEdited covers the ordinary real shape an
// exact-key-set rule missed: a workspace copied and migrated from both
// trees, then edited so one copy carries a key the other lacks. On a real
// vault that was .../okta-mcp-server/.env in two trees, one of which had
// gained OKTA_PRIVATE_KEY — same file, four identical values, and neither
// copy reported. It must pair, must say which keys are not in every copy,
// and must offer NO removal pick: retiring either would drop a secret.
func TestSameFileFindingsCopiedThenEdited(t *testing.T) {
	wide := dupTestGroup("okta-mcp-server", "~/Desktop/Share/ws/mcp_servers/okta-mcp-server/.env",
		true, []string{"okta-mcp-server"}, map[string]string{
			"OKTA_CLIENT_ID": "id", "OKTA_KEY_ID": "kid", "OKTA_ORG_URL": "url",
			"OKTA_SCOPES": "scopes", "OKTA_PRIVATE_KEY": "pem",
		})
	narrow := dupTestGroup("okta-mcp-server-2", "~/Documents/ws/mcp_servers/okta-mcp-server/.env",
		true, []string{"okta-mcp-server-2"}, map[string]string{
			"OKTA_CLIENT_ID": "id", "OKTA_KEY_ID": "kid", "OKTA_ORG_URL": "url",
			"OKTA_SCOPES": "scopes",
		})
	fs := sameFileFindings(map[string]*dupGroup{
		"okta-mcp-server": wide, "okta-mcp-server-2": narrow,
	})
	if len(fs) != 1 {
		t.Fatalf("a copied-then-edited pair must still report, got %+v", fs)
	}
	f := fs[0]
	if len(f.Keys) != 4 {
		t.Errorf("Keys must be the SHARED set, got %v", f.Keys)
	}
	if strings.Join(f.ExtraKeys, ",") != "OKTA_PRIVATE_KEY" {
		t.Errorf("ExtraKeys = %v, want the key only one copy holds", f.ExtraKeys)
	}
	if f.RemoveGroup != "" || f.RemoveCommand != "" || f.Prunable {
		t.Errorf("no removal pick when a copy holds keys the other lacks, got %+v", f)
	}

	// Siblings from ONE file (one .mcp.json, one profile per server) share
	// the origin tail but no keys: they must never pair.
	caido := dupTestGroup("mcp-caido-2", "~/Documents/ws/.mcp.json", true, nil,
		map[string]string{"CAIDO_URL": "u"})
	okta := dupTestGroup("mcp-okta-mcp-server", "~/Documents/ws/.mcp.json", true, nil,
		map[string]string{"OKTA_ORG_URL": "o", "OKTA_SCOPES": "s"})
	if fs = sameFileFindings(map[string]*dupGroup{
		"mcp-caido-2": caido, "mcp-okta-mcp-server": okta,
	}); len(fs) != 0 {
		t.Errorf("servers from one config file are siblings, not copies, got %+v", fs)
	}
}

// TestRemedyScopeWithheldWhenItWouldTakeAProtectedGroup reproduces the
// incident this guard exists for. `jit migrate remove <file>` resolves up
// to the .jit project owning the file and un-migrates EVERYTHING under it.
// On a real vault, retiring the stale mcp-caido-2 meant naming
// ~/Desktop/Share/ai_security_workspace/.mcp.json — whose project also
// owned okta-mcp-server, the copy holding an OKTA_PRIVATE_KEY its twin
// lacked, which the SAME report had just refused to nominate for removal.
// Running the caido remedy deleted it. The remedy must now be withheld.
func TestRemedyScopeWithheldWhenItWouldTakeAProtectedGroup(t *testing.T) {
	home := withFixtureHome(t)
	ws := filepath.Join(home, "Share", "ai_security_workspace")
	nested := filepath.Join(ws, "ai_tooling", "mcp_servers", "okta-mcp-server")
	if err := os.MkdirAll(filepath.Join(ws, ".jit"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := func(p string) string { return "~" + strings.TrimPrefix(p, home) }

	// The caido pair: identical values, so it would normally get a pick.
	caidoOld := dupTestGroup("mcp-caido", "~/Documents/ai_security_workspace/.mcp.json",
		true, []string{"mcp-caido"}, map[string]string{"CAIDO_URL": "u"})
	caidoNew := dupTestGroup("mcp-caido-2", rel(filepath.Join(ws, ".mcp.json")),
		true, []string{"mcp-caido-2"}, map[string]string{"CAIDO_URL": "u"})
	// The okta pair, under the SAME project: one copy holds a key the other
	// lacks, so it gets no pick — and must not be collateral damage.
	oktaWide := dupTestGroup("okta-mcp-server", rel(filepath.Join(nested, ".env")),
		true, []string{"okta-mcp-server"}, map[string]string{
			"OKTA_CLIENT_ID": "id", "OKTA_ORG_URL": "url", "OKTA_PRIVATE_KEY": "pem",
		})
	oktaNarrow := dupTestGroup("okta-mcp-server-2", "~/Documents/ai_security_workspace/ai_tooling/mcp_servers/okta-mcp-server/.env",
		true, []string{"okta-mcp-server-2"}, map[string]string{
			"OKTA_CLIENT_ID": "id", "OKTA_ORG_URL": "url",
		})

	fs := sameFileFindings(map[string]*dupGroup{
		"mcp-caido": caidoOld, "mcp-caido-2": caidoNew,
		"okta-mcp-server": oktaWide, "okta-mcp-server-2": oktaNarrow,
	})
	var caido *dupFinding
	for i := range fs {
		if fs[i].Groups[0] == "mcp-caido" {
			caido = &fs[i]
		}
	}
	if caido == nil {
		t.Fatalf("expected a caido finding, got %+v", fs)
	}
	if caido.RemoveCommand != "" || caido.Prunable {
		t.Errorf("remedy must be withheld when its project scope covers a protected group, got %+v", caido)
	}
	if caido.RemoveGroup != "mcp-caido-2" {
		t.Errorf("the stale copy is still named, only the command goes, got %q", caido.RemoveGroup)
	}
	if caido.RemoveBlockedBy != "okta-mcp-server" {
		t.Errorf("the blocking GROUP must be named, got %q", caido.RemoveBlockedBy)
	}
	if !slices.Contains(caido.AlsoRemoves, "okta-mcp-server") {
		t.Errorf("AlsoRemoves must list the group the command would take, got %v", caido.AlsoRemoves)
	}

	// Rendering says why, and offers no command to run.
	var buf bytes.Buffer
	printDupFinding(&buf, *caido)
	out := buf.String()
	if !strings.Contains(out, "no safe one-command fix") || !strings.Contains(out, "okta-mcp-server") {
		t.Errorf("report must explain the withheld remedy, got:\n%s", out)
	}
	// The prose may NAME the command while explaining; what must never
	// appear is the runnable directive line with a path to copy.
	if strings.Contains(out, glyphAction+" jit migrate remove") {
		t.Errorf("no runnable migrate remove line may be offered, got:\n%s", out)
	}
}

// TestRemedyNamesWhatElseItTakes: when the project scope is safe, the
// remedy still has to say what else goes with it and that the files come
// back as plaintext — neither is conveyed by the command name.
func TestRemedyNamesWhatElseItTakes(t *testing.T) {
	home := withFixtureHome(t)
	ws := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(ws, ".jit"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := func(p string) string { return "~" + strings.TrimPrefix(p, home) }

	a := dupTestGroup("app", "~/Documents/proj/.env", true, []string{"app"},
		map[string]string{"API_KEY": "k"})
	b := dupTestGroup("app-2", rel(filepath.Join(ws, ".env")), true, []string{"app-2"},
		map[string]string{"API_KEY": "k"})
	// An unrelated group under the same project, in no finding of its own.
	side := dupTestGroup("sidecar", rel(filepath.Join(ws, "sub", ".env")), true, nil,
		map[string]string{"OTHER": "v"})

	fs := sameFileFindings(map[string]*dupGroup{"app": a, "app-2": b, "sidecar": side})
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %+v", fs)
	}
	if !slices.Contains(fs[0].AlsoRemoves, "sidecar") {
		t.Errorf("AlsoRemoves must name the co-located group, got %v", fs[0].AlsoRemoves)
	}
	var buf bytes.Buffer
	printDupFinding(&buf, fs[0])
	out := buf.String()
	for _, want := range []string{"jit migrate remove", "also holds sidecar", "return to plaintext"} {
		if !strings.Contains(out, want) {
			t.Errorf("remedy missing %q, got:\n%s", want, out)
		}
	}
}

// TestPruneDuplicatesOnlyTouchesTheSafeShape is the guard that matters:
// --prune must delete ONLY a stale copy whose origin file is gone and which
// nothing references, must leave every other shape alone, and must say so
// rather than reporting a clean sweep. Declining the confirmation deletes
// nothing at all.
func TestPruneDuplicatesOnlyTouchesTheSafeShape(t *testing.T) {
	withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	for _, p := range []string{"dead/KEY", "live/KEY", "wired/KEY"} {
		if err := v.Set(p, []byte("value")); err != nil {
			t.Fatalf("Set(%s): %v", p, err)
		}
	}
	findings := []dupFinding{
		{ // the safe shape
			Groups: []string{"keep", "dead"}, RemoveGroup: "dead", ValuesMatch: true,
			RemoveCommand: "jit vault duplicates --prune",
			Prunable:      true, RemovePaths: []string{"dead/KEY"},
		},
		{ // file still on disk: migrate remove's job
			Groups: []string{"keep2", "live"}, RemoveGroup: "live", ValuesMatch: true,
			RemoveCommand: "jit migrate remove /x/live/.env",
		},
		{ // still referenced: a per-path rm decision
			Groups: []string{"keep3", "wired"}, RemoveGroup: "wired", ValuesMatch: true,
			RemoveCommand: "jit vault rm wired/KEY",
		},
		{ // diverged: never jit's call
			Groups: []string{"a", "b"}, ValuesMatch: false,
		},
	}

	// Declining the confirmation must delete nothing.
	vaultDuplicatesYes, vaultDuplicatesFormat = false, "text"
	cmd, buf := newDupPruneCmd(strings.NewReader("")) // EOF == declined
	if err := pruneDuplicates(cmd, v, findings); err != nil {
		t.Fatalf("pruneDuplicates (declined): %v", err)
	}
	if !strings.Contains(buf.String(), "Aborted. Nothing was deleted.") {
		t.Errorf("declining must abort, got:\n%s", buf.String())
	}
	for _, p := range []string{"dead/KEY", "live/KEY", "wired/KEY"} {
		if ok, _ := v.Exists(p); !ok {
			t.Errorf("%s deleted despite a declined confirmation", p)
		}
	}

	// The report names what it will delete, and only that.
	out := buf.String()
	if !strings.Contains(out, "dead/KEY") {
		t.Errorf("prune plan must name the prunable path, got:\n%s", out)
	}
	for _, unsafe := range []string{"live/KEY", "wired/KEY"} {
		if strings.Contains(out, "  "+glyphBullet+" "+unsafe) {
			t.Errorf("prune plan must not list %s, got:\n%s", unsafe, out)
		}
	}
	// And it accounts for what it left behind, with each command.
	for _, want := range []string{
		"Left alone, 3 findings need a command only you should run:",
		"jit migrate remove /x/live/.env",
		"jit vault rm wired/KEY",
		"copies have diverged, compare them first",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prune must report what it skipped (%q), got:\n%s", want, out)
		}
	}

	// Nothing prunable at all -> says so plainly, still accounts for the rest.
	cmd, buf = newDupPruneCmd(strings.NewReader(""))
	if err := pruneDuplicates(cmd, v, findings[1:]); err != nil {
		t.Fatalf("pruneDuplicates (nothing prunable): %v", err)
	}
	if !strings.Contains(buf.String(), "Nothing to prune") ||
		!strings.Contains(buf.String(), "Left alone, 3 findings") {
		t.Errorf("empty prune must explain, got:\n%s", buf.String())
	}
}

// newDupPruneCmd builds a cobra command wired to a buffer and the given
// stdin, for driving confirmPrompt without the real terminal.
func newDupPruneCmd(stdin io.Reader) (*cobra.Command, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetIn(stdin)
	return cmd, buf
}

// TestGatherDupGroups drives the gather stage against a real (fixture)
// vault: values decrypt and digest per key, a uniform origin is kept while
// mixed origins claim nothing, and a gone origin file reads as such.
func TestGatherDupGroups(t *testing.T) {
	withFixtureHome(t)
	cwd := t.TempDir()
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}

	origin := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(origin, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := func(path, value, org string) {
		t.Helper()
		if err := v.SetWithMeta(path, []byte(value), vault.Meta{Class: vault.ClassDotenv, Origin: org}); err != nil {
			t.Fatalf("SetWithMeta(%s): %v", path, err)
		}
	}
	set("alpha/A", "one", origin)
	set("alpha/B", "two", origin)
	set("beta/A", "one", "/gone/elsewhere/.env")
	set("mixed/X", "x", origin)
	set("mixed/Y", "y", "/somewhere/else/.env")

	groups, compared, err := gatherDupGroups(v, root, cwd,
		[]string{"alpha/A", "alpha/B", "beta/A", "mixed/X", "mixed/Y"})
	if err != nil {
		t.Fatalf("gatherDupGroups: %v", err)
	}
	if compared != 5 {
		t.Errorf("compared = %d, want 5", compared)
	}
	a := groups["alpha"]
	if a == nil || a.origin != origin || !a.originExists {
		t.Fatalf("alpha = %+v, want its uniform, existing origin", a)
	}
	b := groups["beta"]
	if b == nil || b.originExists {
		t.Fatalf("beta = %+v, want a gone origin", b)
	}
	// Same plaintext must digest identically across groups; different
	// plaintext must not.
	if a.hashes["A"] != b.hashes["A"] {
		t.Errorf("identical values must share a digest")
	}
	if a.hashes["A"] == a.hashes["B"] {
		t.Errorf("different values must not share a digest")
	}
	if m := groups["mixed"]; m == nil || m.origin != "" {
		t.Errorf("mixed = %+v, mixed origins must claim nothing", m)
	}
}
