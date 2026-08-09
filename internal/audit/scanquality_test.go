// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderTriage renders the triage view the way a real run does, so these
// tests judge what a reader actually sees rather than an intermediate struct.
func renderTriage(t *testing.T, findings []Finding, home string) string {
	t.Helper()
	annotateCauseGroups(findings)
	var buf bytes.Buffer
	WriteTriageReport(&buf, findings, ScanSummary{}, home, ComputeCoverage(home, "", findings))
	return buf.String()
}

// TestProtectInPlaceCommandSurvivesNarrowTerminals is the regression guard for
// the bug this whole pass started from: kindProtectInPlace's arrow is
// `jit migrate <path> --mount`, and the renderer used to truncate it because
// it asked `kind == kindArchived` instead of asking whether the action was a
// command. At 80 columns the path was cut mid-component and --mount vanished
// silently, which is worse than a cut command — it reads as complete and does
// something else.
func TestProtectInPlaceCommandSurvivesNarrowTerminals(t *testing.T) {
	const home = "/Users/alex"
	const path = home + "/.cursor/plugins/cache/cursor-public/snowflake-cursor-plugin/60fbf039c5c3b8dcddc9a07618cc154072b1d5e1/mcp.json"
	key := "Snowflake/header:Authorization"
	out := renderTriage(t, []Finding{{
		RecordID: "s", FindingType: FindingTypeMCPEmbeddedSecret,
		KeyName: &key, Severity: SeverityHigh, Remedy: RemedyManual,
		FilePath: path, Evidence: "credential in a header block",
	}}, home)

	if !strings.Contains(out, "--mount") {
		t.Errorf("the --mount flag was truncated off the command:\n%s", out)
	}
	// The whole path, not a prefix of it. Asserted on the un-flattened output
	// because the command prints as one logical line.
	if !strings.Contains(out, "~/.cursor/plugins/cache/cursor-public/snowflake-cursor-plugin/60fbf039c5c3b8dcddc9a07618cc154072b1d5e1/mcp.json --mount") {
		t.Errorf("command is not intact:\n%s", out)
	}
}

// TestSentenceArrowsWrapInsteadOfLosingTheirTail guards the other half of the
// same renderer. Prose arrows used to truncate on the theory that they merely
// restated the group header; the ones that did have been rewritten to carry
// what the header cannot, so a cut tail now loses meaning rather than
// repetition.
func TestSentenceArrowsWrapInsteadOfLosingTheirTail(t *testing.T) {
	const home = "/Users/alex"
	name := "OpenSSH Private Key"
	line := 2866
	out := renderTriage(t, []Finding{{
		RecordID: "h", FindingType: FindingTypeShellHistorySecret,
		KeyName: &name, Line: &line,
		Severity: SeverityCritical, Remedy: RemedyManual,
		FilePath: home + "/.zsh_history",
		Evidence: "private key material typed at the shell",
	}}, home)

	if strings.Contains(out, "delet…") || strings.Contains(out, "authorized, then…") {
		t.Errorf("a prose arrow was truncated mid-sentence:\n%s", out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "then delete those lines by hand") {
		t.Errorf("the arrow lost its closing clause:\n%s", out)
	}
}

// TestIdenticalArchivedFindingsRenderOnce covers the six-line stutter: six
// findings identical in every field that matters (type, nil key name,
// severity, remedy) differing only by path rendered as six consecutive
// "! An exposed credential" items, because mergeManualGroups keyed on an
// action that names the file and so was unique per finding.
func TestIdenticalArchivedFindingsRenderOnce(t *testing.T) {
	const home = "/Users/alex"
	const root = home + "/Documents/archive/workspace"
	paths := []string{
		root + "/.env",
		root + "/tooling/falcon/.env",
		root + "/tooling/okta/.env",
		root + "/tooling/urlscan/.env",
		root + "/scripts/descope/.env",
		root + "/scripts/jamf/.env",
	}
	var findings []Finding
	for i, p := range paths {
		findings = append(findings, Finding{
			RecordID: string(rune('a' + i)), FindingType: FindingTypeEnvFilePresent,
			Severity: SeverityHigh, Remedy: RemedyMigrate, Archived: true,
			FilePath: p, Evidence: "secret-shaped",
		})
	}
	out := renderTriage(t, findings, home)

	if got := strings.Count(out, "An exposed credential"); got != 1 {
		t.Errorf("rendered the same finding %d times, want 1:\n%s", got, out)
	}
	// Merging must not cost the reader an address: all six still print.
	for _, p := range paths {
		tail := p[len(home):]
		if !strings.Contains(strings.Join(strings.Fields(out), " "), tail[strings.LastIndex(tail, "/"):]) {
			t.Errorf("address for %s disappeared in the merge:\n%s", p, out)
		}
	}
	// And the one command must cover the whole group, not the sample it was
	// built from — the failure mode groupManualByAction's shortening exists
	// to prevent, which the merge briefly reintroduced by collapsing the
	// items the shortening iterates.
	if !strings.Contains(out, "jit migrate ~/Documents/archive/workspace") {
		t.Errorf("group command does not name the common archived parent:\n%s", out)
	}
}

// TestEnvFileReferenceIsNotASecondSecret pins the ledger half: an MCP config
// that reaches a credential file with --env-file is a link, and the .env it
// names is where the credential is counted. Counting both scored two secrets
// for one credential.
func TestEnvFileReferenceIsNotASecondSecret(t *testing.T) {
	const home = "/Users/alex"
	const envPath = home + "/work/mcp/okta/.env"
	server := "okta-mcp-server"

	envFinding := Finding{
		RecordID: "e", FindingType: FindingTypeEnvFilePresent,
		Severity: SeverityHigh, Remedy: RemedyMigrate,
		FilePath: envPath, Evidence: "contains a PKCS8 private key",
	}
	reference := Finding{
		RecordID: "m", FindingType: FindingTypeMCPEmbeddedSecret,
		KeyName: &server, Severity: SeverityHigh, Remedy: RemedyMigrate,
		FilePath: home + "/work/.mcp.json", OriginPath: envPath,
		Evidence: "reads credentials from ~/work/mcp/okta/.env",
	}

	both := ComputeCoverage(home, "", []Finding{envFinding, reference})
	if both.Exposed != 1 {
		t.Errorf("exposed = %d, want 1: the reference and its target are one credential", both.Exposed)
	}

	// The other direction is the reason the finding exists at all: a target
	// the .env name gate never reported has no finding of its own, so the
	// reference is the only evidence and must still count.
	alone := ComputeCoverage(home, "", []Finding{reference})
	if alone.Exposed != 1 {
		t.Errorf("exposed = %d, want 1: an unreported target leaves the reference as the only evidence", alone.Exposed)
	}
}

// TestLedgerExclusionsAreAllReadableFromTheRecord is the NDJSON-parity guard.
// A consumer recomputing coverage needs every exclusion the tally applies to
// be visible in the serialized record; source_example was not, which left the
// stream unable to reproduce secrets_total.
func TestLedgerExclusionsAreAllReadableFromTheRecord(t *testing.T) {
	raw, err := json.Marshal(Finding{
		RecordType: RecordTypeFinding, FindingType: FindingTypeExposedSecret,
		Severity: SeverityHigh, FilePath: "/Users/alex/src/patterns.go",
		SourceExample: true, OriginPath: "/Users/alex/work/.env",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"source_example", "origin_path", "test_fixture", "severity"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("%q is not in the record, so a consumer cannot reproduce the ledger: %s", field, raw)
		}
	}
	if decoded["source_example"] != true {
		t.Errorf("source_example did not round-trip: %s", raw)
	}
}

// TestAssignedCredentialNameNamesTheVariable covers the case the feature was
// built for: a live release-publishing token and a test vector share a vendor,
// so they share a title, and only the name beside the value tells them apart.
// atMarker locates the credential inside a test line by a caller-chosen
// substring, so the offset handed to assignedCredentialName is the REAL start
// of the matched value — not an approximation. The first draft of these tests
// computed the offset with strings.LastIndexAny(line, "\"= "), which lands
// wherever the last quote/equals/space happens to be rather than where the
// value begins, so it exercised inputs no scanner ever produces; that is how
// a leaking extractor passed its own guard (found in review 2026-08-09).
func atMarker(t *testing.T, line, marker string) int {
	t.Helper()
	i := strings.Index(line, marker)
	if i < 0 {
		t.Fatalf("marker %q not in %q", marker, line)
	}
	return i
}

func TestAssignedCredentialNameNamesTheVariable(t *testing.T) {
	// marker is where the credential value starts; the offset is derived from
	// it, never guessed.
	for _, tc := range []struct{ name, line, marker, want string }{{
		name:   "gh secret set names its positional, not the --body flag",
		line:   `gh secret set HOMEBREW_TAP_GITHUB_TOKEN -R jitpass/jit --body "github_pat_x"`,
		marker: "github_pat_x",
		want:   "HOMEBREW_TAP_GITHUB_TOKEN",
	}, {
		name:   "gh secret set inside a JSON-escaped transcript line",
		line:   `{"display":"gh secret set HOMEBREW_TAP_GITHUB_TOKEN -R x --body \"github_pat_x\""}`,
		marker: "github_pat_x",
		want:   "HOMEBREW_TAP_GITHUB_TOKEN",
	}, {
		name:   "an env assignment",
		line:   `OKTA_KEY_ID=abcdefghijklmnop`,
		marker: "abcdefghijklmnop",
		want:   "OKTA_KEY_ID",
	}, {
		name:   "a json field",
		line:   `{"id_token":"eyJhbGciOi"}`,
		marker: "eyJhbGciOi",
		want:   "id_token",
	}, {
		name:   "a yaml key",
		line:   `    client-key-data: LS0tLS1CRUdJTg==`,
		marker: "LS0tLS1",
		want:   "client-key-data",
	}, {
		name:   "a json field inside an escaped transcript",
		line:   `{"text":"config \"id_token\":\"eyJhbGciOi\""}`,
		marker: "eyJhbGciOi",
		want:   "id_token",
	}, {
		name:   "nothing to say about a bare value on its own line",
		line:   `eyJhbGciOi`,
		marker: "eyJhbGciOi",
		want:   "",
	}, {
		name:   "no credential-shaped name in reach",
		line:   `curl -H "Accept: application/json" https://api.example.com/ eyJhbGciOi`,
		marker: "eyJhbGciOi",
		want:   "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			at := atMarker(t, tc.line, tc.marker)
			if got := assignedCredentialName(tc.line, at); got != tc.want {
				t.Errorf("assignedCredentialName(%q, %d) = %q, want %q", tc.line, at, got, tc.want)
			}
		})
	}
}

// TestAssignedCredentialNameNeverPrintsAValue is the guard behind the report's
// closing promise that no secret value is ever printed in full. It is the
// corpus an adversarial review (2026-08-09) used to walk credential material
// out of the proximity-based first draft: a password from a curl -u line, one
// from a JSON blob, a fragment of an AWS secret key. Every case pairs a real
// credential (matchStart) with adjacent text engineered to satisfy
// LooksLikeSecretKey/writtenLikeAName — the extractor must print nothing.
func TestAssignedCredentialNameNeverPrintsAValue(t *testing.T) {
	const tok = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	for _, tc := range []struct{ name, line string }{
		{"curl -u userinfo password",
			`curl -u admin:S3cret-Passw0rd https://api.example.com/x?t=` + tok},
		{"a password in a connection string",
			`psql "postgres://app:Tr0ub4dor-Pass@db/x" ` + tok},
		{"a password field beside a token field",
			`{"password":"Hunter2-Pass","token":"` + tok + `"}`},
		{"a base64 secret split on + and /",
			`export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY ` + tok},
		{"an Authorization header value",
			`-H "Authorization: Bearer Sekr3t-Val" ` + tok},
		{"an undifferentiated lowercase run",
			`psql "postgres://app:mysecretpassword@db/x" ` + tok},
		{"a long opaque run that reads like markers",
			`TOKENSECRETKEYPASSWORDTOKENSECRETKEYPASSWORDTOKENSECRETKEY ` + tok},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := strings.Index(tc.line, tok)
			got := assignedCredentialName(tc.line, at)
			if got != "" && strings.Contains(tc.line[:at], got) {
				t.Errorf("printed %q, a fragment of the preceding text, from %q", got, tc.line)
			}
		})
	}
}

// TestAssignedCredentialNameNeverLeaksRandomBlobs is the property form of the
// guard: a high-entropy value adjacent to a credential must never be printed,
// whatever bytes it happens to contain. The proximity draft leaked 111 of
// 20,000 such blobs (one in full, because it contained "sKEY"); the structural
// extractor must leak none. Seeded, so a failure reproduces exactly.
func TestAssignedCredentialNameNeverLeaksRandomBlobs(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	const tok = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 20000; n++ {
		b := make([]byte, 44)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		blob := string(b)
		line := "some output " + blob + " then " + tok
		at := strings.Index(line, tok)
		if got := assignedCredentialName(line, at); got != "" && strings.Contains(blob, got) {
			t.Fatalf("leaked %q from random blob %q", got, blob)
		}
	}
}

// TestAssignedNameIsDroppedWhenConstituentsDisagree keeps a merged block from
// attributing one credential's name to another: two different variables folded
// into one item have no single name to show.
func TestAssignedNameIsDroppedWhenConstituentsDisagree(t *testing.T) {
	const home = "/Users/alex"
	vendor := "JSON Web Token (JWT)"
	mk := func(id, path, name string) Finding {
		return Finding{
			RecordID: id, FindingType: FindingTypeExposedSecret,
			KeyName: &vendor, Severity: SeverityHigh, Remedy: RemedyManual,
			FilePath: path, AssignedName: name, Evidence: "vendor format",
		}
	}
	out := renderTriage(t, []Finding{
		mk("a", home+"/one.txt", "SERVICE_A_TOKEN"),
		mk("b", home+"/two.txt", "SERVICE_B_TOKEN"),
	}, home)

	if strings.Contains(out, "SERVICE_A_TOKEN") && strings.Contains(out, "SERVICE_B_TOKEN") {
		return // rendered as separate items, each correctly named
	}
	if strings.Contains(out, "assigned to") {
		t.Errorf("a merged item claims one constituent's name for both:\n%s", out)
	}
}

// TestLineHintNotClaimedForAMultiFileGroup guards the coordinate-vs-address
// mismatch: f.Line is the worst finding's line in ITS file, so a cause group
// spanning several files must not print "at line N" (wrong for every file but
// one). It falls back to the self-identifying grep instead.
func TestLineHintNotClaimedForAMultiFileGroup(t *testing.T) {
	const home = "/Users/alex"
	vendor := "JSON Web Token (JWT)"
	ln1, ln2 := 12, 3740
	mk := func(id, path string, line int) Finding {
		l := line
		return Finding{
			RecordID: id, FindingType: FindingTypeExposedSecret,
			KeyName: &vendor, Severity: SeverityHigh, Remedy: RemedyManual,
			FilePath: path, Line: &l, Occurrences: 1, Evidence: "vendor format",
		}
	}
	// One credential (shared cause group) in two files.
	a := mk("x", home+"/proj/.env", ln1)
	b := mk("x", home+"/backup/.env.bak", ln2)
	cg := "sharedcause"
	a.CauseGroup, b.CauseGroup = cg, cg
	out := renderTriage(t, []Finding{a, b}, home)

	// Each file carries its OWN line, attached to its own name — no bare
	// "at line N" that a reader could read as applying to the wrong file.
	if !strings.Contains(out, ".env:12") || !strings.Contains(out, ".env.bak:3740") {
		t.Errorf("each file must show its own line:\n%s", out)
	}
	if strings.Contains(out, "grep") {
		t.Errorf("a grep hint survived for a finding whose lines are known:\n%s", out)
	}
	// A single-file finding gets the compact one-liner form.
	solo := renderTriage(t, []Finding{mk("y", home+"/only.env", 5)}, home)
	if !strings.Contains(solo, "~/only.env:5") {
		t.Errorf("single-file finding lost its coordinate:\n%s", solo)
	}
}

// TestCoordinateHintsAreNotCollapsedIntoAGrep guards the other regression:
// three secrets that each know their own line must keep those lines, not be
// folded into one group-wide grep that names none of them.
func TestCoordinateHintsAreNotCollapsedIntoAGrep(t *testing.T) {
	const home = "/Users/alex"
	vendor := "JSON Web Token (JWT)"
	mk := func(id, path string, line int) Finding {
		l := line
		return Finding{
			RecordID: id, FindingType: FindingTypeExposedSecret,
			KeyName: &vendor, Severity: SeverityHigh, Remedy: RemedyManual,
			ProductionIndicatorMatch: true,
			FilePath:                 path, Line: &l, Occurrences: 1, Evidence: "vendor format",
		}
	}
	out := renderTriage(t, []Finding{
		mk("a", home+"/Downloads/a.json", 10),
		mk("b", home+"/Downloads/b.json", 20),
		mk("c", home+"/Downloads/c.json", 30),
	}, home)

	// Every distinct coordinate survives, attached to its own file; no
	// group-wide glob grep replaces them.
	for _, want := range []string{"a.json:10", "b.json:20", "c.json:30"} {
		if !strings.Contains(out, want) {
			t.Errorf("coordinate %q folded away:\n%s", want, out)
		}
	}
	if strings.Contains(out, "*.json") || strings.Contains(out, "grep") {
		t.Errorf("distinct coordinates were collapsed into a grep:\n%s", out)
	}
}

// TestFolderGroupedListing pins the tier-1 addressing: a multi-file secret is
// listed grouped by folder (folder header once, files beneath with lines),
// relevance-ordered so an ordinary location leads and archived/Downloads sink,
// with no grep for findings whose lines are known.
func TestFolderGroupedListing(t *testing.T) {
	const home = "/Users/alex"
	vendor := "JSON Web Token (JWT)"
	mk := func(id, path string, line int) Finding {
		l := line
		return Finding{
			RecordID: id, FindingType: FindingTypeExposedSecret,
			KeyName: &vendor, Severity: SeverityHigh, Remedy: RemedyManual,
			ProductionIndicatorMatch: true,
			FilePath:                 path, Line: &l, Occurrences: 1, Evidence: "x",
		}
	}
	// One secret (shared cause) in: a working dir, an archived tree, ~/Downloads.
	cg := "cg1"
	fs := []Finding{
		mk("s", home+"/work/reports/out.html", 40),
		mk("s", home+"/Documents/archive/old/out.html", 41),
		mk("s", home+"/Downloads/out.html", 42),
	}
	for i := range fs {
		fs[i].CauseGroup = cg
	}
	out := renderTriage(t, fs, home)

	// Folder headers present, each file under its folder with its line.
	for _, want := range []string{
		"~/work/reports/", "out.html:40",
		"~/Documents/archive/old/", "out.html:41",
		"~/Downloads/", "out.html:42",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("listing missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "grep") || strings.Contains(out, "… and") {
		t.Errorf("a grep or an elision survived a fully-located finding:\n%s", out)
	}
	// Relevance order: the working dir's header precedes the archived one, and
	// the archived one precedes... actually Downloads(1) sorts before archive(2),
	// so order is work(0) < Downloads(1) < archive(2).
	iWork := strings.Index(out, "~/work/reports/")
	iDown := strings.Index(out, "~/Downloads/")
	iArch := strings.Index(out, "~/Documents/archive/old/")
	if !(iWork < iDown && iDown < iArch) {
		t.Errorf("folders not relevance-ordered (work=%d downloads=%d archive=%d):\n%s", iWork, iDown, iArch, out)
	}
}

// TestMCPFindingCarriesALine is the tier-2 guard for structured findings: an
// mcp_embedded_secret is placed at the line its key sits on, so the report
// shows "mcp.json:N" instead of a grep locator. The JSON parser threw the
// offset away; mcpFindingLine re-derives it from the raw text.
func TestMCPFindingCarriesALine(t *testing.T) {
	raw := []byte(`{
  "mcpServers": {
    "snowflake": {
      "url": "https://x",
      "headers": {
        "Authorization": "Bearer sk-abc"
      }
    }
  }
}`)
	name := "snowflake/header:Authorization"
	f := Finding{KeyName: &name, rawValue: "Bearer sk-abc"}
	if got := mcpFindingLine(raw, f); got != 6 {
		t.Errorf("value anchor: line = %d, want 6", got)
	}
	// With no usable value (JSON-escaped in the real file), fall back to the
	// key — same line here, one above in pretty JSON, never a value.
	f2 := Finding{KeyName: &name}
	if got := mcpFindingLine(raw, f2); got != 6 {
		t.Errorf("key fallback: line = %d, want 6", got)
	}
	// An args index is not a real JSON key, so it stays lineless rather than
	// matching something unrelated.
	argName := "snowflake/args[2]"
	if got := mcpFindingLine(raw, Finding{KeyName: &argName}); got != 0 {
		t.Errorf("args index should not match a key: line = %d, want 0", got)
	}
}

// TestEnvFindingCarriesALine is the tier-2 guard for env files: the file-level
// finding points at the variable that drove it, in the severity switch's
// priority order.
func TestEnvFindingCarriesALine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	// Line 1 a plain setting, line 2 a secret-shaped name, line 3 a prod key.
	body := "REGION=us-east-1\nAPI_KEY=abcdefghijklmnop\nPROD_DATABASE_URL=postgres://u:p@h/d\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, found, err := buildEnvFileFinding(Config{HomeDir: dir}, path, false)
	if err != nil || !found {
		t.Fatalf("buildEnvFileFinding: found=%v err=%v", found, err)
	}
	// Production indicator wins the priority, so the line is the prod var's (3).
	if f.Line == nil || *f.Line != 3 {
		t.Errorf("line = %v, want 3 (the production-indicator variable)", f.Line)
	}
}

// TestUnresolvedReferenceIsNotASecret pins jit's premise for the header/env
// scanners: a value that only REFERENCES a secret (a shell expansion, a
// placeholder) is not a secret at rest, however the header is named. A real
// token — even an opaque one behind "Bearer " — still is.
func TestUnresolvedReferenceIsNotASecret(t *testing.T) {
	refs := []string{
		"${SNOWFLAKE_PAT_TOKEN}",
		"Bearer ${SNOWFLAKE_PAT_TOKEN}",
		"$GH_TOKEN",
		"token $GH_TOKEN",
		"$(op read op://vault/item/token)",
		"`cat ~/.token`",
		"<your-token-here>",
		"Bearer <PASTE_TOKEN>",
	}
	for _, v := range refs {
		if !LooksLikeUnresolvedReference(v) {
			t.Errorf("%q should be a reference, not a secret", v)
		}
	}
	secrets := []string{
		"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
		"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		"Bearer 8f3a9c2b1d4e6f7a0b9c8d7e6f5a4b3c2d1e0f9a",
		"sk-proj-abcdefghijklmnopqrstuvwxyz",
		"", // empty is handled by callers, not a reference
		"Bearer",
	}
	for _, v := range secrets {
		if LooksLikeUnresolvedReference(v) {
			t.Errorf("%q was wrongly treated as a mere reference", v)
		}
	}
}

// TestRealHeaderTokenStillFlagged is the other-direction guard: dropping
// references must not blind the header scanner to a genuine opaque token.
func TestRealHeaderTokenStillFlagged(t *testing.T) {
	entry := mcpServerEntry{Headers: map[string]string{
		"Authorization": "Bearer ghp_0123456789abcdefghijklmnopqrstuvwxyz",
	}}
	got := scanMCPServerHeaders(Config{}, "/x/mcp.json", "srv", entry)
	if len(got) != 1 {
		t.Fatalf("a real token in an Authorization header must be flagged, got %d findings", len(got))
	}
	// And the reference form produces nothing.
	ref := mcpServerEntry{Headers: map[string]string{
		"Authorization": "Bearer ${SNOWFLAKE_PAT_TOKEN}",
	}}
	if got := scanMCPServerHeaders(Config{}, "/x/mcp.json", "srv", ref); len(got) != 0 {
		t.Errorf("a ${...} reference must not be flagged, got %d findings", len(got))
	}
}
