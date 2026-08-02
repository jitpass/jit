// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/mount"
)

// k8sDataFixture is a data:-only manifest: values already base64, one doc,
// comments and blank lines that must survive templating verbatim.
const k8sDataFixture = `# app database credentials
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
data:
  username: YWRtaW4=
  password: aHVudGVyMg==
`

// k8sStringDataFixture uses the stringData: convenience form, which the
// migration must convert to data: so decoys are rejectable.
const k8sStringDataFixture = `apiVersion: v1
kind: Secret
metadata:
  name: api-token
stringData:
  token: sk-live-abc123
`

func TestClassifyK8sDataManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, k8sDataFixture)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil || plan == nil {
		t.Fatalf("Classify: plan=%v reason=%q err=%v", plan, reason, err)
	}
	if plan.convertedStringData {
		t.Error("data-only manifest reported a stringData conversion")
	}

	wantVars := []string{"SECRET_DB_CREDS_USERNAME", "SECRET_DB_CREDS_PASSWORD"}
	values := map[string]string{}
	for i, e := range plan.entries {
		if e.varName != wantVars[i] {
			t.Errorf("entry %d var = %q, want %q (file order)", i, e.varName, wantVars[i])
		}
		values[e.varName] = e.vaultValue
	}
	// data: values are stored verbatim (already base64), so rendering the
	// template with the vault values must reproduce the original file
	// byte-for-byte — comments, blank lines, trailing newline, everything.
	rendered := mount.FormatTemplate(plan.template, values)
	if string(rendered) != k8sDataFixture {
		t.Errorf("render(template, real values) != original\n--- got ---\n%s\n--- want ---\n%s", rendered, k8sDataFixture)
	}
}

func TestClassifyK8sDataManifestDecoyIsRejectableBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, k8sDataFixture)

	plan, _, err := ClassifyK8sSecretManifest(path)
	if err != nil || plan == nil {
		t.Fatalf("Classify: %v", err)
	}
	real := map[string]string{}
	for _, e := range plan.entries {
		real[e.varName] = e.vaultValue
	}
	decoy := mount.FormatTemplate(plan.template, mount.DecoyValues(real))

	// The decoy manifest must still parse as YAML (kubectl reaches the
	// base64 decode) and every decoy data: value must be INVALID base64
	// (kubectl/apiserver then rejects it loudly — the whole point).
	var doc struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(decoy, &doc); err != nil {
		t.Fatalf("decoy manifest no longer parses as YAML: %v", err)
	}
	if len(doc.Data) != 2 {
		t.Fatalf("decoy data has %d entries, want 2", len(doc.Data))
	}
	for k, v := range doc.Data {
		if !strings.HasPrefix(v, "jit-hidden-") {
			t.Errorf("decoy %s = %q, want a jit-hidden-* placeholder", k, v)
		}
		if _, err := base64.StdEncoding.DecodeString(v); err == nil {
			t.Errorf("decoy value %q decodes as valid base64 — a decoy could be silently applied to a cluster", v)
		}
	}
}

func TestClassifyK8sStringDataConvertsToData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app-secret.yaml")
	writeFile(t, path, k8sStringDataFixture)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil || plan == nil {
		t.Fatalf("Classify: plan=%v reason=%q err=%v", plan, reason, err)
	}
	if !plan.convertedStringData {
		t.Fatal("stringData manifest did not report conversion")
	}
	if len(plan.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(plan.entries))
	}
	e := plan.entries[0]
	if e.varName != "SECRET_API_TOKEN_TOKEN" {
		t.Errorf("var = %q", e.varName)
	}
	// Vault stores base64(plaintext): the template's section is data: now.
	if got, _ := base64.StdEncoding.DecodeString(e.vaultValue); string(got) != "sk-live-abc123" {
		t.Errorf("vault value %q does not decode to the original plaintext", e.vaultValue)
	}

	rendered := mount.FormatTemplate(plan.template, map[string]string{e.varName: e.vaultValue})
	var doc struct {
		Data       map[string]string `yaml:"data"`
		StringData map[string]string `yaml:"stringData"`
	}
	if err := yaml.Unmarshal(rendered, &doc); err != nil {
		t.Fatalf("rendered manifest does not parse: %v\n%s", err, rendered)
	}
	if len(doc.StringData) != 0 {
		t.Errorf("rendered manifest still has stringData: %v", doc.StringData)
	}
	if got, _ := base64.StdEncoding.DecodeString(doc.Data["token"]); string(got) != "sk-live-abc123" {
		t.Errorf("rendered data.token = %q, want base64 of the original plaintext", doc.Data["token"])
	}
	// The plaintext itself must be gone from the template.
	if strings.Contains(string(plan.template), "sk-live-abc123") {
		t.Error("plaintext secret survived in the template")
	}
}

func TestClassifyK8sRefusals(t *testing.T) {
	cases := []struct {
		name, content, wantReason string
	}{
		{
			name: "both sections in one doc",
			content: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
				"data:\n  a: YWRtaW4=\nstringData:\n  b: plain\n",
			wantReason: "both data: and stringData:",
		},
		{
			name: "block scalar value",
			content: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
				"data:\n  cert: |\n    YWRtaW4=\n    YWRtaW4=\n",
			wantReason: "multi-line block scalar",
		},
		{
			name: "flow style section",
			content: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
				"stringData: {token: hunter2}\n",
			wantReason: "not a plain block mapping",
		},
		{
			name: "duplicate value bytes",
			content: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
				"data:\n  a: YWRtaW4=\n  b: YWRtaW4=\n",
			wantReason: "exactly once",
		},
		{
			name: "pre-existing placeholder literal",
			content: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
				"data:\n  a: YWRtaW4=\n# note: ${SECRET_X_A}\n",
			wantReason: "already contains the literal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secret.yaml")
			writeFile(t, path, tc.content)
			plan, reason, err := ClassifyK8sSecretManifest(path)
			if err != nil {
				t.Fatalf("Classify err: %v", err)
			}
			if plan != nil {
				t.Fatal("expected refusal, got a plan")
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason = %q, want substring %q", reason, tc.wantReason)
			}
		})
	}
}

func TestClassifyK8sTemplatedManifestRefused(t *testing.T) {
	// Stock Helm Secret templates whose control-flow / templated keys make
	// the file fail YAML parsing. Each MUST become a refusal, never an
	// anonymous error that falls through to the loose-file migrator (which
	// would serve the stringData: values back as plaintext decoys a bare
	// kubectl apply ships to a cluster). Adversarial-QA CRITICAL, 2026-08-02.
	fixtures := map[string]string{
		"control-flow": "{{- if .Values.enabled }}\napiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
			"stringData:\n  TOKEN: jit-e2e-jwt\n{{- end }}\n",
		"range-block": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\nstringData:\n" +
			"{{- range .Values.secrets }}\n  {{ .name }}: {{ .value }}\n{{- end }}\n",
		"colon-in-template-key": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {{ printf \"%s: %s\" .A .B }}\n" +
			"stringData:\n  TOKEN: jit-e2e\n",
	}
	for name, content := range fixtures {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tpl-secret.yaml")
			writeFile(t, path, content)

			plan, reason, err := ClassifyK8sSecretManifest(path)
			if err != nil {
				t.Fatalf("Classify err: %v", err)
			}
			if plan != nil {
				t.Fatal("a templated (unparseable) kind: Secret file must be refused, not migrated")
			}
			if !strings.Contains(reason, "does not parse as YAML") {
				t.Errorf("reason = %q, want the templated-manifest refusal", reason)
			}
		})
	}
}

func TestClassifyK8sPlaceholderValuesNotVaulted(t *testing.T) {
	// Whole-value template/env placeholders are not secrets: vaulting one
	// freezes the placeholder text and breaks the pipeline meant to fill it.
	content := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
		"stringData:\n  a: ${DB_PASSWORD}\n  b: $(SOME_VAR)\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, content)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil {
		t.Fatalf("Classify err: %v", err)
	}
	if plan != nil {
		t.Fatalf("placeholder-only manifest should not migrate, got a plan")
	}
	if !strings.Contains(reason, "template placeholders") {
		t.Errorf("reason = %q, want the placeholder skip note", reason)
	}
}

func TestClassifyK8sMaskedValuesGiveRefusalNote(t *testing.T) {
	// scan flags a masked/partially-encrypted Secret as holding movable
	// values; migrate skips masked values. Without a note that is a silent
	// dead-end ("scan says migrate, migrate says nothing"). QA MINOR.
	content := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
		"stringData:\n  a: REDACTED\n  b: \"********\"\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, content)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil {
		t.Fatalf("Classify err: %v", err)
	}
	if plan != nil {
		t.Fatal("masked-only manifest should not migrate")
	}
	if !strings.Contains(reason, "masked") {
		t.Errorf("reason = %q, want a masked-values note (not a silent skip)", reason)
	}
}

func TestClassifyK8sEmptyFlowSectionIsCleanSkip(t *testing.T) {
	// `data: {}` exposes nothing; it must be a clean skip, not a "not a
	// plain block mapping" refusal (which would contradict a harmless file).
	content := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\ndata: {}\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, content)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil {
		t.Fatalf("Classify err: %v", err)
	}
	if plan != nil || reason != "" {
		t.Errorf("empty data: {} should be a clean skip, got plan=%v reason=%q", plan, reason)
	}
}

func TestClassifyK8sSkipsNonTargets(t *testing.T) {
	cases := []struct {
		name, content string
	}{
		{"sealed secret", "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: x\nspec:\n  encryptedData:\n    a: AgBy8f==\n"},
		{"fully sops encrypted", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\ndata:\n  a: ENC[AES256_GCM,data:abc]\nsops:\n  version: 3.8.1\n"},
		{"empty scaffold", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n"},
		{"not a secret", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secret.yaml")
			writeFile(t, path, tc.content)
			plan, reason, err := ClassifyK8sSecretManifest(path)
			if err != nil {
				t.Fatalf("Classify err: %v", err)
			}
			if plan != nil || reason != "" {
				t.Errorf("plan=%v reason=%q, want clean skip", plan, reason)
			}
		})
	}
}

func TestClassifyK8sMultiDocPreservesOtherDocs(t *testing.T) {
	content := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\ndata:\n  mode: fast\n" +
		"---\n" + k8sDataFixture
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, content)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil || plan == nil {
		t.Fatalf("Classify: plan=%v reason=%q err=%v", plan, reason, err)
	}
	// Only the Secret doc's values become placeholders; the ConfigMap's
	// data: (same section name, different kind) stays verbatim.
	if !strings.Contains(string(plan.template), "mode: fast") {
		t.Error("ConfigMap content did not survive verbatim")
	}
	if len(plan.entries) != 2 {
		t.Errorf("entries = %d, want 2 (Secret doc only)", len(plan.entries))
	}
}

func TestK8sVarNameCollisionSuffix(t *testing.T) {
	content := k8sDataFixture + "---\n" + k8sDataFixture
	// Same doc twice would duplicate value bytes; vary the second doc's
	// values so only the NAMES collide.
	content = strings.Replace(content, "YWRtaW4=", "cm9vdA==", 1)
	content = strings.Replace(content, "aHVudGVyMg==", "cGFzczI=", 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, content)

	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil || plan == nil {
		t.Fatalf("Classify: plan=%v reason=%q err=%v", plan, reason, err)
	}
	var names []string
	for _, e := range plan.entries {
		names = append(names, e.varName)
	}
	want := []string{
		"SECRET_DB_CREDS_USERNAME", "SECRET_DB_CREDS_PASSWORD",
		"SECRET_DB_CREDS_USERNAME_2", "SECRET_DB_CREDS_PASSWORD_2",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestDiscoverK8sSecretManifests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "db-secrets.yaml"), k8sDataFixture)
	writeFile(t, filepath.Join(dir, "app.yaml"), k8sDataFixture)           // name gate: not matched in a walk
	writeFile(t, filepath.Join(dir, "secret-notes.yaml"), "just: notes\n") // name matches, content doesn't
	writeFile(t, filepath.Join(dir, "mixed-secret.yaml"),
		"apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\ndata:\n  a: YWRtaW4=\nstringData:\n  b: plain\n")

	found, complex, err := DiscoverK8sSecretManifests(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 1 || filepath.Base(found[0]) != "db-secrets.yaml" {
		t.Errorf("found = %v, want just db-secrets.yaml", found)
	}
	if len(complex) != 1 || filepath.Base(complex[0]) != "mixed-secret.yaml" {
		t.Errorf("complex = %v, want just mixed-secret.yaml", complex)
	}

	// A root that IS the file bypasses the "secret" name gate — content
	// decides, matching scan's explicitly-named-file behavior.
	found, _, err = DiscoverK8sSecretManifests(filepath.Join(dir, "app.yaml"))
	if err != nil {
		t.Fatalf("Discover(file): %v", err)
	}
	if len(found) != 1 {
		t.Errorf("naming app.yaml directly: found = %v, want the file itself", found)
	}
}

func TestApplyK8sSecretManifestRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, k8sDataFixture)

	v := newTestVault(t)
	result, err := ApplyK8sSecretManifest(v, home, path)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.ProfileName != "secret" {
		t.Errorf("ProfileName = %q, want secret (file basename)", result.ProfileName)
	}
	if result.ConvertedStringData {
		t.Error("data-only manifest reported conversion")
	}

	// The file is now a FIFO; the template exists; vault leaf == manifest
	// key with the base64 value stored verbatim.
	info, err := os.Lstat(path)
	if err != nil || info.Mode().IsRegular() {
		t.Fatalf("path is still a regular file after Apply (err=%v)", err)
	}
	tmpl, err := os.ReadFile(result.TemplatePath)
	if err != nil {
		t.Fatalf("template missing: %v", err)
	}
	if !strings.Contains(string(tmpl), "${SECRET_DB_CREDS_PASSWORD}") {
		t.Errorf("template lacks the password placeholder:\n%s", tmpl)
	}
	got, err := v.Get(result.ProfileName + "/SECRET_DB_CREDS_PASSWORD")
	if err != nil || string(got) != "aHVudGVyMg==" {
		t.Errorf("vault value = %q err=%v, want the verbatim base64", got, err)
	}

	// A second Apply on the now-FIFO path must fail loudly, not block.
	if _, err := ApplyK8sSecretManifest(v, home, path); err == nil {
		t.Error("Apply on an already-mounted path should fail")
	}
}

func TestApplyK8sSecretManifestUndoRestoresOriginalBytes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	writeFile(t, path, k8sStringDataFixture)

	v := newTestVault(t)
	result, err := ApplyK8sSecretManifest(v, home, path)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.ConvertedStringData {
		t.Fatal("expected a stringData conversion for this fixture")
	}

	// Simulate `jit migrate undo`: the FIFO is retired and the exact
	// original bytes come back — including the stringData: layout the
	// template had rewritten to data:.
	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	restored := false
	for _, rec := range LatestBackups(recs) {
		if err := RestoreFromBackup(v, rec); err != nil {
			t.Fatalf("RestoreFromBackup(%s): %v", rec.OriginalPath, err)
		}
		restored = true
	}
	if !restored {
		t.Fatal("no backup record to restore")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading restored manifest: %v", err)
	}
	if string(got) != k8sStringDataFixture {
		t.Errorf("restored manifest not byte-identical:\n got: %q\nwant: %q", got, k8sStringDataFixture)
	}
}

func TestApplyK8sSecretManifestRefusalMutatesNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	content := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n" +
		"data:\n  a: YWRtaW4=\nstringData:\n  b: plain\n"
	writeFile(t, path, content)

	v := newTestVault(t)
	if _, err := ApplyK8sSecretManifest(v, home, path); err == nil {
		t.Fatal("Apply on a refused manifest should fail")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != content {
		t.Errorf("refused file was mutated (err=%v):\n%s", err, data)
	}
}
