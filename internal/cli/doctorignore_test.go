// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/migrate"
)

// execDoctorSub runs `jit doctor <sub> args...` with every ignore flag
// reset, the way execDoctor resets doctor's own, and the ignore clock
// pinned to the preview's date.
func execDoctorSub(t *testing.T, args ...string) (string, error) {
	t.Helper()
	doctorIgnoreKind, doctorIgnoreFormat = "", "text"
	doctorUnignoreKind, doctorUnignoreFormat, doctorUnignoreAll = "", "text", false
	doctorIgnoreCmd.Flags().Visit(func(f *pflag.Flag) { f.Changed = false })
	doctorUnignoreCmd.Flags().Visit(func(f *pflag.Flag) { f.Changed = false })
	origNow := doctorIgnoreNow
	doctorIgnoreNow = func() time.Time { return time.Date(2026, 9, 19, 12, 0, 0, 0, time.Local) }
	t.Cleanup(func() { doctorIgnoreNow = origNow })
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"doctor"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

// ignoreFixture is the preview's machine: aws-dev and aws-admin not logged
// in, aws-qa a real [profile missing], and mcp-okta-mcp-server in both
// [missing] and [config deleted].
func ignoreFixture(t *testing.T) string {
	t.Helper()
	home := notLoggedInFixture(t)
	installClissoCapture(t, home)
	writeFixtureProfile(t, home, "mcp-okta-mcp-server",
		"OKTA_ORG_URL: mcp-okta-mcp-server/OKTA_ORG_URL\nOKTA_SCOPES: mcp-okta-mcp-server/OKTA_SCOPES\n")
	writeOwners(t, home, "mcp-okta-mcp-server", filepath.Join(home, "Documents", "ai_security_workspace", ".mcp.json"))
	writeMCPConfig(t, filepath.Join(home, "Security-Ops", ".mcp.json"),
		map[string]string{"okta-mcp-server": mcpServerJSON(testJitPath(t), "mcp-okta-mcp-server")})
	return home
}

func doctorJSON(t *testing.T, args ...string) (doctorResult, error) {
	t.Helper()
	out, err := execDoctor(t, append([]string{"--format", "json"}, args...)...)
	var result doctorResult
	if jerr := json.Unmarshal([]byte(out), &result); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	return result, err
}

func exitCode(err error) int {
	var exit *ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.Code
	default:
		return 1
	}
}

// The receipts, byte for byte as the preview approved them.
func TestDoctorIgnoreReceipts(t *testing.T) {
	ignoreFixture(t)
	out, err := execDoctorSub(t, "ignore", "aws-dev", "aws-admin")
	if err != nil {
		t.Fatalf("ignore: %v", err)
	}
	want := "✓ ignored aws-dev · not logged in\n" +
		"✓ ignored aws-admin · not logged in\n" +
		"  each comes back if its ~/.aws/config entry changes\n" +
		"  → jit doctor unignore aws-dev aws-admin\n" +
		"    to show them again\n"
	if out != want {
		t.Errorf("advisory receipt:\n%s\nwant:\n%s", out, want)
	}

	out, err = execDoctorSub(t, "ignore", "aws-qa")
	if err != nil {
		t.Fatalf("ignore: %v", err)
	}
	want = "✓ ignored aws-qa · profile missing\n" +
		"  aws --profile qa still fails; doctor just stops counting it\n" +
		"  → jit doctor unignore aws-qa\n" +
		"    to show it again\n"
	if out != want {
		t.Errorf("problem receipt:\n%s\nwant:\n%s", out, want)
	}
}

func TestDoctorIgnoreSingularAdvisory(t *testing.T) {
	ignoreFixture(t)
	out, _ := execDoctorSub(t, "ignore", "aws-dev")
	if !strings.Contains(out, "  it comes back if its ~/.aws/config entry changes\n") ||
		!strings.Contains(out, "    to show it again\n") {
		t.Errorf("one ignore reads in the singular:\n%s", out)
	}
}

// A name in two sections writes nothing and names both, suggesting the
// advisory one; an unknown name is exit 1 too.
func TestDoctorIgnoreAmbiguousAndUnknown(t *testing.T) {
	home := ignoreFixture(t)
	_, err := execDoctorSub(t, "ignore", "aws-dev", "mcp-okta-mcp-server")
	if exitCode(err) != 1 {
		t.Fatalf("ambiguous name: exit %d, want 1 (%v)", exitCode(err), err)
	}
	want := "jit doctor ignore: mcp-okta-mcp-server is in 2 findings, pick one\n" +
		"  missing · OKTA_ORG_URL, OKTA_SCOPES\n" +
		"  config deleted · tool okta-mcp-server\n" +
		"  → jit doctor ignore --kind config-deleted mcp-okta-mcp-server"
	if got := FormatError(err); got != want {
		t.Errorf("ambiguity:\n%s\nwant:\n%s", got, want)
	}
	if _, serr := os.Stat(doctorIgnorePath(home)); !errors.Is(serr, os.ErrNotExist) {
		t.Errorf("a refused ignore must write nothing, not even aws-dev: %v", serr)
	}

	_, err = execDoctorSub(t, "ignore", "no-such-thing")
	if exitCode(err) != 1 || !strings.Contains(err.Error(), "nothing doctor reports is named no-such-thing") {
		t.Errorf("unknown name: %v", err)
	}

	for _, kind := range []string{"config-deleted", "config_deleted", "[config deleted]"} {
		if _, err := execDoctorSub(t, "ignore", "--kind", kind, "mcp-okta-mcp-server"); err != nil {
			t.Errorf("--kind %s: %v", kind, err)
		}
	}
	if _, err := execDoctorSub(t, "ignore", "--kind", "bogus", "aws-dev"); exitCode(err) != 1 {
		t.Errorf("unknown --kind: %v", err)
	}
}

// Ignored findings leave the counts: ok, the exit code and --strict.
func TestDoctorIgnoreExitCodes(t *testing.T) {
	ignoreFixture(t)
	if _, err := execDoctorSub(t, "ignore", "--kind", "config-deleted", "mcp-okta-mcp-server"); err != nil {
		t.Fatal(err)
	}
	if _, err := execDoctorSub(t, "ignore", "aws-dev", "aws-admin", "aws-qa"); err != nil {
		t.Fatal(err)
	}
	_, err := execDoctor(t)
	if exitCode(err) != doctorProblemsExitCode || err.Error() != "jit doctor: 2 problems found — exit 2" {
		t.Errorf("only [missing] still counts: %v", err)
	}
	if _, err := execDoctorSub(t, "ignore", "--kind", "missing", "mcp-okta-mcp-server"); err != nil {
		t.Fatal(err)
	}
	result, err := doctorJSON(t)
	if err != nil || !result.OK || len(result.Problems) != 0 {
		t.Errorf("everything broken is ignored: err=%v ok=%v problems=%+v", err, result.OK, result.Problems)
	}
	// --strict counts the warnings that are left, never the ignored ones.
	// Whatever else this machine warns about (completion, say) is ignored
	// through its own argv, as the app would.
	for _, f := range result.Warnings {
		if f.Kind != kindWrapEnv {
			if _, err := execDoctorSub(t, f.Ignore.Argv[2:]...); err != nil {
				t.Fatalf("ignoring %+v by its argv: %v", f.Ignore, err)
			}
		}
	}
	if _, err := execDoctor(t, "--strict"); err != nil {
		t.Errorf("--strict with every warning ignored: %v", err)
	}
}

// The report's [ignored] group, and --show-ignored, as the preview shows
// them; and a changed entry comes back with its └ line.
func TestDoctorIgnoredGroupRendersTheApprovedShape(t *testing.T) {
	home := ignoreFixture(t)
	if _, err := execDoctorSub(t, "ignore", "aws-dev", "aws-admin"); err != nil {
		t.Fatal(err)
	}
	out, _ := execDoctor(t)
	if strings.Contains(out, "[not logged in]") {
		t.Errorf("ignored rows must leave their section:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n[ignored]  2\n  → jit doctor --show-ignored\n") {
		t.Errorf("expected the [ignored] group last:\n%s", out)
	}

	out, _ = execDoctor(t, "--show-ignored")
	want := "[ignored]  2\n" +
		"  ○ aws-dev · not logged in · since 2026-09-19\n" +
		"  ○ aws-admin · not logged in · since 2026-09-19\n" +
		"  → jit doctor unignore <name>\n"
	if !strings.HasSuffix(out, want) {
		t.Errorf("--show-ignored:\n%s\nwant suffix:\n%s", out, want)
	}

	cfg, err := os.ReadFile(migrate.AWSConfigPath(home))
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(cfg), "--profile aws-dev\n", "--profile aws-dev\nregion = us-east-1\n", 1)
	writeProfileAt(t, migrate.AWSConfigPath(home), edited)
	out, _ = execDoctor(t)
	want = "[not logged in]\n" +
		"  clisso makes this profile the first time you log in\n" +
		"  ○ aws --profile dev · ~/.aws/config [profile dev]\n" +
		"    └ was ignored; that entry changed since\n" +
		"  → clisso get dev\n"
	if !strings.Contains(out, want) {
		t.Errorf("a changed entry comes back:\n%s\nwant:\n%s", out, want)
	}
	if !strings.HasSuffix(out, "\n[ignored]\n  → jit doctor --show-ignored\n") {
		t.Errorf("aws-admin is still ignored:\n%s", out)
	}

	// Ignored problems keep their red glyph under --show-ignored.
	if _, err := execDoctorSub(t, "ignore", "aws-qa"); err != nil {
		t.Fatal(err)
	}
	out, _ = execDoctor(t, "--show-ignored")
	if !strings.Contains(out, "  ✗ aws-qa · profile missing · since 2026-09-19\n") {
		t.Errorf("an ignored problem is still a problem row:\n%s", out)
	}
}

// The JSON contract the app is built against.
func TestDoctorIgnoreJSONShape(t *testing.T) {
	home := ignoreFixture(t)
	result, _ := doctorJSON(t)
	if result.Ignored == nil || len(result.Ignored) != 0 {
		t.Errorf("ignored is always present, [] when empty: %+v", result.Ignored)
	}
	for _, f := range append(result.Problems, result.Warnings...) {
		if f.Ignore == nil || f.Ignore.Kind != f.Kind || f.Ignore.Name == "" ||
			!reflect.DeepEqual(f.Ignore.Argv, []string{"jit", "doctor", "ignore", "--kind", string(f.Kind), f.Ignore.Name}) {
			t.Errorf("finding without a usable ignore ref: %+v", f)
		}
		if f.IgnoredSince != "" || f.Unignore != nil || f.Severity != "" || f.IgnoreChanged {
			t.Errorf("ignored-only fields on a shown finding: %+v", f)
		}
	}

	out, err := execDoctorSub(t, "ignore", "--format", "json", "aws-dev", "aws-qa")
	if err != nil {
		t.Fatal(err)
	}
	var res doctorIgnoreResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	wantRes := doctorIgnoreResult{
		Ignored:   []doctorIgnoreItem{{Kind: kindNotLoggedIn, Name: "aws-dev"}, {Kind: kindProfileMissing, Name: "aws-qa"}},
		Unignored: []doctorIgnoreItem{},
	}
	if !reflect.DeepEqual(res, wantRes) {
		t.Errorf("ignore --format json = %+v, want %+v", res, wantRes)
	}
	if !strings.Contains(out, `"unignored": []`) || strings.Contains(out, `"error"`) {
		t.Errorf("unignored is [] and error absent on success:\n%s", out)
	}

	result, err = doctorJSON(t)
	if exitCode(err) != doctorProblemsExitCode {
		t.Errorf("[missing] still counts: %v", err)
	}
	if len(result.Ignored) != 2 {
		t.Fatalf("ignored = %+v", result.Ignored)
	}
	byName := map[string]checkFinding{}
	for _, f := range result.Ignored {
		byName[f.Profile] = f
	}
	dev, qa := byName["aws-dev"], byName["aws-qa"]
	for _, c := range []struct {
		f        checkFinding
		kind     checkKind
		name     string
		severity string
	}{{dev, kindNotLoggedIn, "aws-dev", "warning"}, {qa, kindProfileMissing, "aws-qa", "problem"}} {
		if c.f.Kind != c.kind || c.f.IgnoredSince != "2026-09-19" || c.f.Severity != c.severity ||
			c.f.Unignore == nil || !reflect.DeepEqual(c.f.Unignore.Argv, []string{"jit", "doctor", "unignore", "--kind", string(c.kind), c.name}) ||
			c.f.Ignore == nil || c.f.Ignore.Name != c.name || c.f.Profile != c.name || len(c.f.Launchers) != 1 {
			t.Errorf("ignored %s = %+v", c.name, c.f)
		}
	}
	if len(dev.Fixes) != 1 || dev.Fixes[0].Command != "clisso get dev" {
		t.Errorf("an ignored finding keeps its fixes: %+v", dev.Fixes)
	}

	writeProfileAt(t, migrate.AWSConfigPath(home), strings.Replace(mustRead(t, migrate.AWSConfigPath(home)),
		"--profile aws-dev\n", "--profile aws-dev\nregion = eu-west-1\n", 1))
	result, _ = doctorJSON(t)
	changed := 0
	for _, f := range result.Warnings {
		if f.IgnoreChanged {
			changed++
			if f.Profile != "aws-dev" {
				t.Errorf("only aws-dev changed: %+v", f)
			}
		}
	}
	if changed != 1 || len(result.Ignored) != 1 {
		t.Errorf("aws-dev comes back with ignore_changed: changed=%d ignored=%+v", changed, result.Ignored)
	}

	out, err = execDoctorSub(t, "ignore", "--format", "json", "no-such-thing")
	if exitCode(err) != 1 {
		t.Errorf("JSON unknown name: exit %d", exitCode(err))
	}
	res = doctorIgnoreResult{}
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil || res.Error == "" || res.Ignored == nil || len(res.Ignored) != 0 {
		t.Errorf("JSON error result = %+v (%v)\n%s", res, jerr, out)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The store is 0600, written only by ignore/unignore; doctor never writes
// it, and unignore takes entries back out.
func TestDoctorIgnoreStore(t *testing.T) {
	home := ignoreFixture(t)
	path := doctorIgnorePath(home)
	if _, err := execDoctor(t); err == nil {
		t.Fatal("fixture should have problems")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor must not write the ignore store: %v", err)
	}
	if _, err := execDoctorSub(t, "ignore", "aws-dev", "aws-admin"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("store mode = %o, want 600", info.Mode().Perm())
	}
	before := mustRead(t, path)
	_, _ = execDoctor(t, "--show-ignored")
	_, _ = doctorJSON(t)
	if mustRead(t, path) != before {
		t.Error("doctor rewrote the ignore store")
	}
	st, err := loadDoctorIgnores(home)
	if err != nil || len(st.Entries) != 2 || st.Entries[0].Name != "aws-admin" || st.Entries[0].Since != "2026-09-19" ||
		len(st.Entries[0].Fingerprint) != 32 {
		t.Errorf("store = %+v (%v)", st, err)
	}

	out, err := execDoctorSub(t, "unignore", "aws-dev")
	if err != nil || out != "✓ unignored aws-dev · not logged in\n" {
		t.Errorf("unignore = %q (%v)", out, err)
	}
	if _, err := execDoctorSub(t, "unignore", "aws-dev"); exitCode(err) != 1 {
		t.Errorf("unignoring what isn't ignored is exit 1: %v", err)
	}
	out, err = execDoctorSub(t, "unignore", "--format", "json", "--all")
	var res doctorIgnoreResult
	if jerr := json.Unmarshal([]byte(out), &res); err != nil || jerr != nil ||
		!reflect.DeepEqual(res.Unignored, []doctorIgnoreItem{{Kind: kindNotLoggedIn, Name: "aws-admin"}}) {
		t.Errorf("unignore --all = %+v (%v, %v)", res, err, jerr)
	}
	if st, _ := loadDoctorIgnores(home); len(st.Entries) != 0 {
		t.Errorf("--all left %+v", st.Entries)
	}

	// A store that won't parse is refused by the writers, and ignores
	// nothing in the report rather than failing it.
	writeProfileAt(t, path, "{not json")
	if _, err := execDoctorSub(t, "ignore", "aws-dev"); exitCode(err) != 1 {
		t.Errorf("ignore over a broken store: %v", err)
	}
	if mustRead(t, path) != "{not json" {
		t.Error("a broken store must not be overwritten")
	}
	if out, _ := execDoctor(t); !strings.Contains(out, "[not logged in]  2") {
		t.Errorf("a broken store ignores nothing:\n%s", out)
	}
}

// fingerprintFinding builds a unit from findings and returns its
// fingerprint.
func fingerprintOf(findings ...checkFinding) string {
	units := doctorIgnoreUnits(findings)
	if len(units) != 1 {
		panic("one unit expected")
	}
	return units[0].fingerprint
}

// What a fingerprint must ignore (order, counts, dates, evidence) and what
// it must not (the finding's subject, secrets, launchers, record).
func TestDoctorIgnoreFingerprint(t *testing.T) {
	home := withFixtureHome(t)
	awsFile := filepath.Join(home, ".aws", "config")
	writeProfileAt(t, awsFile, "[profile dev]\ncredential_process = x --profile aws-dev\n")
	aws := launchers.Launcher{Kind: launchers.KindAWS, File: awsFile, Detail: "[profile dev]", Profile: "aws-dev"}
	missA := checkFinding{Kind: kindMissing, Profile: "p", Scope: "global", Variable: "A", Path: "p/A", Action: "x"}
	missB := checkFinding{Kind: kindMissing, Profile: "p", Scope: "global", Variable: "B", Path: "p/B"}
	backup := func(d string) checkFinding {
		return checkFinding{Kind: kindBackup, Detail: "secrets have changed since the last vault export (" + d + ")."}
	}
	gone := checkFinding{Kind: kindConfigDeleted, Profile: "mcp-okta", Owners: []string{"/a", "/b"}, Configs: []string{"/c"}}

	same := []struct {
		name string
		a, b []checkFinding
	}{
		{"row order", []checkFinding{missA, missB}, []checkFinding{missB, missA}},
		{"a date in the prose", []checkFinding{backup("2026-09-01")}, []checkFinding{backup("2026-09-19")}},
		{"a count in the prose",
			[]checkFinding{{Kind: kindService, Detail: "so 2 registered mounts aren't being served"}},
			[]checkFinding{{Kind: kindService, Detail: "so 3 registered mounts aren't being served"}}},
		{"the action wording", []checkFinding{missA}, []checkFinding{func() checkFinding { f := missA; f.Action = "y"; return f }()}},
		{"record order", []checkFinding{gone}, []checkFinding{func() checkFinding {
			f := gone
			f.Owners = []string{"/b", "/a"}
			return f
		}()}},
		{"unlaunched counts",
			[]checkFinding{{Kind: kindNoKnownTool, Profile: "t", Path: "/t.yaml", Secrets: 2, SecretsMissing: 0}},
			[]checkFinding{{Kind: kindNoKnownTool, Profile: "t", Path: "/t.yaml", Secrets: 2, SecretsMissing: 1}}},
		{"origin_gone users", []checkFinding{{Kind: kindOriginGone, Path: "~/x", Groups: []string{"g"}, Profiles: []string{"a"}}},
			[]checkFinding{{Kind: kindOriginGone, Path: "~/x", Groups: []string{"g"}, Profiles: []string{"a", "b"}}}},
	}
	for _, c := range same {
		if fingerprintOf(c.a...) != fingerprintOf(c.b...) {
			t.Errorf("%s changed the fingerprint", c.name)
		}
	}

	differ := []struct {
		name string
		a, b []checkFinding
	}{
		{"another secret missing", []checkFinding{missA}, []checkFinding{missA, missB}},
		{"a variable renamed", []checkFinding{missA}, []checkFinding{func() checkFinding { f := missA; f.Variable = "Z"; return f }()}},
		{"a secret path", []checkFinding{missA}, []checkFinding{func() checkFinding { f := missA; f.Path = "q/A"; return f }()}},
		{"stale vs never exported", []checkFinding{backup("2026-09-01")},
			[]checkFinding{{Kind: kindBackup, Detail: "no vault export on record, so the vault only decrypts on this Mac."}}},
		{"a record entry", []checkFinding{gone}, []checkFinding{func() checkFinding {
			f := gone
			f.Owners = []string{"/a"}
			return f
		}()}},
		{"a launching config", []checkFinding{gone}, []checkFinding{func() checkFinding {
			f := gone
			f.Configs = []string{"/c", "/d"}
			return f
		}()}},
	}
	for _, c := range differ {
		if fingerprintOf(c.a...) == fingerprintOf(c.b...) {
			t.Errorf("%s left the fingerprint unchanged", c.name)
		}
	}

	nli := checkFinding{Kind: kindNotLoggedIn, Profile: "aws-dev", File: awsFile, Launchers: []launchers.Launcher{aws}}
	before := fingerprintOf(nli)
	if fingerprintOf(nli) != before {
		t.Error("fingerprint is not deterministic")
	}
	writeProfileAt(t, awsFile, "# a comment\n[profile dev]\n\ncredential_process = x --profile aws-dev\n[profile other]\nregion = x\n")
	if fingerprintOf(nli) != before {
		t.Error("comments, blank lines and other sections are not the entry")
	}
	writeProfileAt(t, awsFile, "[profile dev]\ncredential_process = x --profile aws-dev\nregion = us-east-1\n")
	if fingerprintOf(nli) == before {
		t.Error("editing the [profile dev] entry must change the fingerprint")
	}
}

// Every kind has a name, and the names users type resolve.
func TestDoctorIgnoreNames(t *testing.T) {
	home := withFixtureHome(t)
	for _, k := range allCheckKinds {
		if ignoreName(checkFinding{Kind: k}) == "" {
			t.Errorf("kind %s has no ignore name", k)
		}
	}
	cases := []struct {
		f     checkFinding
		name  string
		typed []string
	}{
		{checkFinding{Kind: kindNotLoggedIn, Profile: "aws-dev"}, "aws-dev", []string{"aws-dev"}},
		{checkFinding{Kind: kindPointerMissing, File: filepath.Join(home, ".clisso.yaml")}, "~/.clisso.yaml",
			[]string{"~/.clisso.yaml", filepath.Join(home, ".clisso.yaml")}},
		{checkFinding{Kind: kindBackup, Detail: "x"}, "backup", []string{"backup", "[backup]", "BACKUP"}},
		{checkFinding{Kind: kindLegacyEnvelope}, "storage-format", []string{"storage-format", "legacy_envelope", "legacy-envelope"}},
		{checkFinding{Kind: kindOrphan, Path: "a/b"}, "orphan", []string{"orphan"}},
		{checkFinding{Kind: kindWrapEnv, Detail: "PATH: shim dir not on PATH"}, "PATH", []string{"PATH"}},
		{checkFinding{Kind: kind1PasswordLink, Path: "okta/TOKEN"}, "okta/TOKEN", []string{"okta/TOKEN"}},
	}
	for _, c := range cases {
		if got := ignoreName(c.f); got != c.name {
			t.Errorf("ignoreName(%s) = %q, want %q", c.f.Kind, got, c.name)
		}
		for _, typed := range c.typed {
			if !ignoreNameMatches(c.f.Kind, c.name, typed) {
				t.Errorf("%q should name %s %q", typed, c.f.Kind, c.name)
			}
		}
	}
	if ignoreNameMatches(kindNotLoggedIn, "aws-dev", "aws-admin") || ignoreNameMatches(kindBackup, "backup", "service") {
		t.Error("names must not match loosely")
	}
}

// A missing secret names the tools that start its profile, in JSON, so
// the app can say which tool won't start without other findings to read.
func TestDoctorMissingCarriesItsProfileLaunchers(t *testing.T) {
	home := ignoreFixture(t)
	result, _ := doctorJSON(t)
	config := filepath.Join(home, "Security-Ops", ".mcp.json")
	n := 0
	for _, f := range result.Problems {
		if f.Kind != kindMissing {
			continue
		}
		n++
		if len(f.Launchers) != 1 || f.Launchers[0].Kind != launchers.KindMCP || f.Launchers[0].File != config ||
			f.Launchers[0].Detail != "okta-mcp-server" || f.Launchers[0].Profile != "mcp-okta-mcp-server" {
			t.Errorf("missing %s launchers = %+v", f.Variable, f.Launchers)
		}
	}
	if n != 2 {
		t.Errorf("want 2 missing findings, got %d", n)
	}
}

// The launchers are JSON only: [missing] reads byte for byte as it did.
func TestDoctorMissingTextUnchangedByLaunchers(t *testing.T) {
	ignoreFixture(t)
	out, _ := execDoctor(t)
	want := "[missing]  2\n" +
		"  ✗ profile \"mcp-okta-mcp-server\" (global): OKTA_ORG_URL →\n" +
		"    mcp-okta-mcp-server/OKTA_ORG_URL, not in the vault\n" +
		"  ✗ profile \"mcp-okta-mcp-server\" (global): OKTA_SCOPES →\n" +
		"    mcp-okta-mcp-server/OKTA_SCOPES, not in the vault\n" +
		"  → jit vault set <path> for each, or jit migrate <path> to convert the files\n" +
		"    they came from\n\n"
	if !strings.Contains(out, want) {
		t.Errorf("[missing] changed:\n%s\nwant:\n%s", out, want)
	}

	outcome, err := gatherDoctorOutcome(nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	var missing, bare []checkFinding
	for _, f := range outcome.Findings {
		if f.Kind == kindMissing {
			if len(f.Launchers) == 0 {
				t.Fatalf("fixture's missing finding has no launchers: %+v", f)
			}
			missing = append(missing, f)
			f.Launchers = nil
			bare = append(bare, f)
		}
	}
	var with, without bytes.Buffer
	writeFindingGroups(&with, glyphRisk, cRisk, missing, false)
	writeFindingGroups(&without, glyphRisk, cRisk, bare, false)
	if with.String() != without.String() {
		t.Errorf("launchers changed the text:\n%s\nvs\n%s", with.String(), without.String())
	}
}

// A tool added or removed is not a change to a [missing] finding: its
// ignore holds.
func TestDoctorIgnoreFingerprintSkipsProfileLaunchers(t *testing.T) {
	home := ignoreFixture(t)
	miss := checkFinding{Kind: kindMissing, Profile: "p", Scope: "global", Variable: "A", Path: "p/A"}
	withTool := miss
	withTool.Launchers = []launchers.Launcher{{Kind: launchers.KindMCP, File: "/x/.mcp.json", Detail: "okta", Profile: "p"}}
	if fingerprintOf(miss) != fingerprintOf(withTool) {
		t.Error("a per-secret finding's launchers must stay out of its fingerprint")
	}

	if _, err := execDoctorSub(t, "ignore", "--kind", "missing", "mcp-okta-mcp-server"); err != nil {
		t.Fatal(err)
	}
	jit := testJitPath(t)
	writeMCPConfig(t, filepath.Join(home, "Security-Ops", ".mcp.json"), map[string]string{
		"okta-mcp-server": mcpServerJSON(jit, "mcp-okta-mcp-server"),
		"okta-second":     mcpServerJSON(jit, "mcp-okta-mcp-server"),
	})
	result, _ := doctorJSON(t)
	for _, f := range result.Problems {
		if f.Kind == kindMissing {
			t.Errorf("a new tool un-ignored [missing]: %+v", f)
		}
	}
	n := 0
	for _, f := range result.Ignored {
		if f.Kind == kindMissing {
			n++
			if len(f.Launchers) != 2 {
				t.Errorf("the ignored finding still lists both tools: %+v", f.Launchers)
			}
		}
	}
	if n != 2 {
		t.Errorf("want both missing rows ignored, got %d", n)
	}
}
