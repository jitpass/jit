// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// K8sSecretManifestMigration describes one Kubernetes Secret manifest turned
// into a live FIFO template mount: every data:/stringData: value moved into
// the vault, the file replaced by a pipe serving the manifest with ${VAR}
// placeholders — real values under a `jit run` grant, decoys otherwise. The
// decoys ("jit-hidden-<VAR>") are never valid base64, so a bare
// `kubectl apply -f` on the decoy fails loudly at the apiserver's base64
// decode instead of writing decoys into a cluster; verified empirically in
// spike/kubectl-fifo-manifest/FINDINGS.md.
type K8sSecretManifestMigration struct {
	Path               string
	ProfileName        string
	ProfilePath        string
	Variables          []string
	BackupPath         string
	NamespaceMovedFrom string
	TemplatePath       string
	// ConvertedStringData is true when the template rewrites a stringData:
	// section to data:. The applied Secret object is identical (the apiserver
	// folds stringData into data anyway), but only data: gives the
	// rejectable-decoy property: stringData accepts ANY string, so a decoy
	// there would be silently applied to a real cluster as the secret's
	// value — the spike proved this, not just the docs.
	ConvertedStringData bool
}

// maxK8sManifestBytes bounds how much manifest a single migrate parse will
// read — same reasoning as audit's maxStructuredParseSize: a manifest is a
// text file a human wrote, and an unbounded read of a walked path is a memory
// amplifier.
const maxK8sManifestBytes = 4 << 20

// k8sManifestEntry is one secret value the migration moves: the vault
// variable name, the exact bytes to substitute out of the file (the needle),
// and the value the vault stores. For a data: entry the vault value is the
// base64 string verbatim, byte-faithful to the file (the kubeconfig
// discipline). For a stringData: entry the vault stores base64(plaintext),
// because the template converts the section to data: and the placeholder
// must render what data: requires.
type k8sManifestEntry struct {
	varName    string
	needle     string
	vaultValue string
	fromString bool
}

// k8sHeaderRename records one stringData: key token to rewrite to data:,
// located by the yaml parser's own position for the key node.
type k8sHeaderRename struct {
	line   int // 1-based
	column int // 1-based
}

// k8sManifestPlan is everything ApplyK8sSecretManifest needs to execute, and
// everything the CLI plan needs to describe: produced by one shared
// extraction path (classifyK8sManifestBytes) so Discover and Apply can never
// disagree about what a file holds (the locateSOPSAgeSecret discipline).
type k8sManifestPlan struct {
	entries             []k8sManifestEntry
	template            []byte
	convertedStringData bool
}

// k8sSecretManifestName reports whether name passes the walk gate for
// Kubernetes Secret manifests — the same deliberately broad gate audit's
// iacNameGates uses (db-secrets.yaml, prod.secret.yml, ...); the structured
// content check is what prevents false positives.
func k8sSecretManifestName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "secret") && k8sYAMLSuffix(lower)
}

func k8sYAMLSuffix(lower string) bool {
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

// DiscoverK8sSecretManifests walks root for plaintext Kubernetes Secret
// manifests this migration can safely convert (found) and ones it recognizes
// but must refuse (complexOnly — block-scalar values, data: mixed with
// stringData:, values that don't locate uniquely), so the plan can say
// "seen, nothing movable" instead of staying silent, the DiscoverTfvarsFiles
// contract.
//
// A root that is itself a regular .yaml/.yml file skips the "secret" name
// gate and lets content decide — `jit scan app.yaml` flags a Secret doc
// inside any explicitly named YAML file, and the scan fix-hint then names
// this path, so migrate must reach the same verdict on it.
func DiscoverK8sSecretManifests(root string) (found, complexOnly []string, err error) {
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return filepath.SkipDir
		}
		if d.IsDir() {
			if skipDiscoveryDir(root, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only, same rule as every other discovery walk:
		// reading a FIFO (an already-migrated file) would block forever.
		if !d.Type().IsRegular() {
			return nil
		}
		if path == root {
			if !k8sYAMLSuffix(strings.ToLower(d.Name())) {
				return nil
			}
		} else if !k8sSecretManifestName(d.Name()) {
			return nil
		}
		plan, reason, cerr := ClassifyK8sSecretManifest(path)
		switch {
		case cerr != nil:
			return nil // unreadable/unparseable — leave it to scan's reporting
		case plan != nil:
			found = append(found, path)
		case reason != "":
			complexOnly = append(complexOnly, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("walking %s: %w", root, walkErr)
	}
	sort.Strings(found)
	sort.Strings(complexOnly)
	return found, complexOnly, nil
}

// ClassifyK8sSecretManifest decides what this migration can do with path:
// a non-nil plan (migratable), a non-empty refusal reason (recognized Secret
// manifest jit must not touch), or neither (not a plaintext Secret manifest
// at all — no Secret docs, fully SOPS-encrypted, empty scaffold).
func ClassifyK8sSecretManifest(path string) (*k8sManifestPlan, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%s is not a regular file (already a live mount?)", path)
	}
	if info.Size() > maxK8sManifestBytes {
		return nil, "larger than migrate's manifest size bound", nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- explicitly-named migrate target, same trust boundary as every Apply* path
	if err != nil {
		return nil, "", err
	}
	plan, reason, err := classifyK8sManifestBytes(data)
	if err != nil && bytes.Contains(data, []byte("kind: Secret")) {
		// A kind: Secret file that doesn't parse as YAML (a Helm template's
		// unquoted {{ }}, a mangled doc) must surface as a REFUSAL, never an
		// anonymous error: an errored classification used to fall through to
		// the loose-file migrator, whose --mount template served the
		// stringData: values back as PLAINTEXT decoys — which a bare
		// `kubectl apply` silently ships to a real cluster, the exact
		// failure the rejectable-decoy design exists to prevent. Found by
		// adversarial QA on a stock Helm Secret template, 2026-08-02.
		return nil, "kind: Secret present but the file does not parse as YAML (a templated manifest?)", nil
	}
	return plan, reason, err
}

// classifyK8sManifestBytes is the single extraction path Discover, the CLI
// plan, and Apply all share. It parses every YAML document, collects the
// plaintext Secret values with their exact file spans, converts stringData:
// headers, and builds the final template — refusing the whole file (reason)
// the moment any part of it can't be handled provably right. Reported,
// never half-migrated.
func classifyK8sManifestBytes(data []byte) (*k8sManifestPlan, string, error) {
	docs, err := decodeK8sSecretDocs(data)
	if err != nil {
		return nil, "", err
	}

	var (
		entries []k8sManifestEntry
		renames []k8sHeaderRename
		// skippedInert counts values passed over as empty, masked, or
		// template/env placeholders. When a file yields NO movable entries
		// but did skip some of these, the file gets a refusal note instead
		// of a silent pass: `jit scan` flags such files as holding movable
		// values, and "scan says migrate, migrate says nothing" with no
		// explanation is a reported dead-end. Fully SOPS-encrypted values
		// (ENC[...]) deliberately don't count — scan doesn't flag those
		// either, so silence agrees with it.
		skippedInert int
		converted    bool
		nameSeen     = map[string]int{}
	)
	for i, doc := range docs {
		dataPairs, reason := sectionPairs(doc.mapValue("data"))
		if reason != "" {
			return nil, reason, nil
		}
		stringPairs, reason := sectionPairs(doc.mapValue("stringData"))
		if reason != "" {
			return nil, reason, nil
		}
		dataEntries, dataInert := plaintextK8sValues(dataPairs)
		stringEntries, stringInert := plaintextK8sValues(stringPairs)
		skippedInert += dataInert + stringInert
		if len(dataEntries) == 0 && len(stringEntries) == 0 {
			continue // empty scaffold or fully protected — nothing exposed
		}
		// One doc mixing both sections would need a real merge (delete
		// stringData lines, splice entries into the data block) — refuse
		// rather than get YAML surgery subtly wrong. kubectl accepts the
		// manifest either way; the user unifies the sections first.
		if len(dataEntries) > 0 && len(stringEntries) > 0 {
			return nil, "a Secret document uses both data: and stringData:", nil
		}

		secretName := doc.metadataName()
		if secretName == "" {
			secretName = fmt.Sprintf("DOC%d", i+1)
		}
		for _, kv := range append(dataEntries, stringEntries...) {
			if kv.value.Kind != yaml.ScalarNode || kv.value.Anchor != "" || kv.value.Alias != nil {
				return nil, "a secret value uses a YAML anchor or non-scalar form", nil
			}
			switch kv.value.Style {
			case yaml.LiteralStyle, yaml.FoldedStyle:
				return nil, "a secret value is a multi-line block scalar", nil
			}
			varName := k8sSecretVarName(secretName, kv.key.Value, nameSeen)
			entries = append(entries, k8sManifestEntry{
				varName:    varName,
				needle:     kv.value.Value,
				vaultValue: k8sVaultValue(kv, len(stringEntries) > 0),
				fromString: len(stringEntries) > 0,
			})
		}
		if len(stringEntries) > 0 {
			key := doc.mapKey("stringData")
			renames = append(renames, k8sHeaderRename{line: key.Line, column: key.Column})
			converted = true
		}
	}
	if len(entries) == 0 {
		if skippedInert > 0 {
			return nil, "its Secret values are empty, masked, or template placeholders; nothing plaintext to move", nil
		}
		return nil, "", nil
	}

	// FormatTemplate is position-blind byte substitution: pre-existing
	// placeholder text for one of OUR names would get the real value written
	// into it at serve time. Unrelated ${OTHER} placeholders (Helm/envsubst
	// pipelines) are left alone by FormatTemplate and are fine.
	for _, e := range entries {
		if bytes.Contains(data, []byte("${"+e.varName+"}")) {
			return nil, "file already contains the literal ${" + e.varName + "}", nil
		}
	}

	template, reason := buildK8sTemplate(data, entries, renames)
	if reason != "" {
		return nil, reason, nil
	}
	return &k8sManifestPlan{entries: entries, template: template, convertedStringData: converted}, "", nil
}

// buildK8sTemplate performs the two rewrites — stringData: headers renamed to
// data:, every secret value span replaced by its ${VAR} placeholder — and
// then proves the result: each placeholder present exactly once, no original
// secret value surviving anywhere, and the whole thing still parseable YAML.
// Any failure refuses the file with a reason instead of shipping a template
// that would serve wrong bytes.
func buildK8sTemplate(data []byte, entries []k8sManifestEntry, renames []k8sHeaderRename) ([]byte, string) {
	// Header renames first, line-wise: they don't move any value span
	// because a rename never shares a line with a value scalar (the
	// single-line entry checks above guarantee values live on their own
	// key: value lines below the header).
	lines := bytes.Split(data, []byte("\n"))
	for _, r := range renames {
		if r.line < 1 || r.line > len(lines) {
			return nil, "stringData: header position out of range"
		}
		line := lines[r.line-1]
		col := r.column - 1
		if col < 0 || col+len("stringData") > len(line) ||
			!bytes.HasPrefix(line[col:], []byte("stringData")) {
			return nil, "stringData: header not found at its parsed position"
		}
		lines[r.line-1] = append(append(append([]byte{}, line[:col]...), []byte("data")...), line[col+len("stringData"):]...)
	}
	template := bytes.Join(lines, []byte("\n"))

	// Value substitution by unique needle, the locateSOPSAgeSecret
	// discipline: the span is provably the one the parse saw only when the
	// value bytes appear exactly once in the whole file. A value that is a
	// substring of another corrupts the longer one's needle; the placeholder
	// and no-value-survives proofs below catch that fail-closed.
	for _, e := range entries {
		needle := []byte(e.needle)
		if bytes.Count(template, needle) != 1 {
			return nil, "a secret value does not appear exactly once in the file"
		}
		template = bytes.Replace(template, needle, []byte("${"+e.varName+"}"), 1)
	}
	for _, e := range entries {
		if bytes.Count(template, []byte("${"+e.varName+"}")) != 1 {
			return nil, "placeholder substitution did not land exactly once"
		}
		if bytes.Contains(template, []byte(e.needle)) {
			return nil, "a secret value survived templating"
		}
	}

	// The served manifest must stay parseable — a template YAML can't
	// produce is worse than no migration.
	dec := yaml.NewDecoder(bytes.NewReader(template))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errIsEOF(err) {
				break
			}
			return nil, "templated manifest no longer parses as YAML"
		}
	}
	return template, ""
}

// k8sSecretVarName derives the vault/template variable for one secret value:
// SECRET_<metadata.name>_<KEY>, uppercased and collapsed to env-style
// characters, with a numeric suffix on collision. The vault leaf and the
// template placeholder are the same string by construction — the tfvars
// idempotency rule claimNamespace depends on.
func k8sSecretVarName(secretName, key string, seen map[string]int) string {
	base := "SECRET_" + looseSecretName(secretName) + "_" + looseSecretName(key)
	seen[base]++
	if seen[base] > 1 {
		return fmt.Sprintf("%s_%d", base, seen[base])
	}
	return base
}

// k8sVaultValue is what the vault stores for one entry: data: values
// verbatim (already base64, byte-faithful round-trip), stringData: values
// base64-encoded here because the template converts that section to data:
// and the placeholder must render valid base64.
func k8sVaultValue(kv k8sPair, fromStringData bool) string {
	if fromStringData {
		return base64.StdEncoding.EncodeToString([]byte(kv.value.Value))
	}
	return kv.value.Value
}

// K8sManifestPreview reports what a plan line can say about path without
// migrating it: how many secret values would move and whether a stringData:
// section would be converted to data:. ok == false when the file isn't
// migratable, in which case the plan leaves the bullet unannotated.
func K8sManifestPreview(path string) (secrets int, convertsStringData bool, ok bool) {
	plan, _, err := ClassifyK8sSecretManifest(path)
	if err != nil || plan == nil {
		return 0, false, false
	}
	return len(plan.entries), plan.convertedStringData, true
}

// ApplyK8sSecretManifest moves every plaintext Secret value in path into v's
// vault under a profile rooted at profilesRoot and replaces the manifest with
// a FIFO serving the ${VAR} template. Same safety ordering as every Apply*:
// vault writes, profile manifest, backup, and template all land before the
// FIFO swap, so a failure partway never leaves the file gone with nothing
// usable in its place. The caller registers the mount from TemplatePath.
func ApplyK8sSecretManifest(v *vault.Vault, profilesRoot, path string) (K8sSecretManifestMigration, error) {
	plan, reason, err := ClassifyK8sSecretManifest(path)
	if err != nil {
		return K8sSecretManifestMigration{}, fmt.Errorf("inspecting %s: %w", path, err)
	}
	if plan == nil {
		if reason == "" {
			reason = "no plaintext Secret values"
		}
		return K8sSecretManifestMigration{}, fmt.Errorf("%s: %s, refusing to half-migrate", path, reason)
	}

	varNames := make([]string, len(plan.entries))
	for i, e := range plan.entries {
		varNames[i] = e.varName
	}

	profileName, profilePath, profEntries, movedFrom, err := claimNamespace(v, profilesRoot, deriveLooseProfileName(path), varNames)
	if err != nil {
		return K8sSecretManifestMigration{}, err
	}

	meta, err := newProvenance(vault.ClassK8sSecret, path)
	if err != nil {
		return K8sSecretManifestMigration{}, err
	}
	for _, e := range plan.entries {
		secretPath := profileName + "/" + e.varName
		if err := v.SetWithMeta(secretPath, []byte(e.vaultValue), meta); err != nil {
			return K8sSecretManifestMigration{}, fmt.Errorf("storing %s in vault: %w", e.varName, err)
		}
		profEntries[e.varName] = secretPath
	}

	if err := writeProfileManifest(profilePath, profEntries, varNames); err != nil {
		return K8sSecretManifestMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return K8sSecretManifestMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".k8s.tmpl"
	if err := os.WriteFile(templatePath, plan.template, 0o600); err != nil { // #nosec G306 G703 -- templatePath derives from claimNamespace's sanitized profile path, not user input
		return K8sSecretManifestMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return K8sSecretManifestMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return K8sSecretManifestMigration{
		Path:                path,
		ProfileName:         profileName,
		ProfilePath:         profilePath,
		Variables:           varNames,
		BackupPath:          backupPath,
		NamespaceMovedFrom:  movedFrom,
		TemplatePath:        templatePath,
		ConvertedStringData: plan.convertedStringData,
	}, nil
}

// --- yaml.Node plumbing -----------------------------------------------------
//
// The migrator works from yaml.Node rather than decoded maps because it needs
// what maps destroy: file order (stable var naming across re-runs), scalar
// styles (block scalars must be refused), and source positions (the
// stringData: header rename). audit's iac.go decodes to typed maps because it
// only judges values; this path rewrites bytes.

// k8sDocNode wraps one parsed document whose kind is Secret.
type k8sDocNode struct {
	root *yaml.Node
}

// k8sPair is one key/value pair of a mapping node.
type k8sPair struct {
	key   *yaml.Node
	value *yaml.Node
}

// decodeK8sSecretDocs parses every document and returns the ones with
// kind: Secret, skipping per-document type oddities the way audit's
// inspectK8sSecretFile does. SealedSecret never matches (exact "Secret").
func decodeK8sSecretDocs(data []byte) ([]k8sDocNode, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []k8sDocNode
	sawDoc := false
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errIsEOF(err) {
				break
			}
			if !sawDoc {
				return nil, err
			}
			break // malformed trailing doc; judge what we already have
		}
		sawDoc = true
		root := &node
		if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
			root = root.Content[0]
		}
		if root.Kind != yaml.MappingNode {
			continue
		}
		doc := k8sDocNode{root: root}
		if kind := doc.scalarValue("kind"); kind != "Secret" {
			continue
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

func errIsEOF(err error) bool {
	return errors.Is(err, io.EOF)
}

// mapKey returns the key node for name in the doc's top-level mapping, or nil.
func (d k8sDocNode) mapKey(name string) *yaml.Node {
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		if d.root.Content[i].Value == name {
			return d.root.Content[i]
		}
	}
	return nil
}

// mapValue returns the value node for name in the doc's top-level mapping,
// or nil.
func (d k8sDocNode) mapValue(name string) *yaml.Node {
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		if d.root.Content[i].Value == name {
			return d.root.Content[i+1]
		}
	}
	return nil
}

func (d k8sDocNode) scalarValue(name string) string {
	if v := d.mapValue(name); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

func (d k8sDocNode) metadataName() string {
	meta := d.mapValue("metadata")
	if meta == nil || meta.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(meta.Content); i += 2 {
		if meta.Content[i].Value == "name" && meta.Content[i+1].Kind == yaml.ScalarNode {
			return meta.Content[i+1].Value
		}
	}
	return ""
}

// sectionPairs returns a data:/stringData: mapping's pairs in file order. A
// present section that isn't a block-style mapping (flow `{k: v}`, a scalar,
// an alias) is REFUSED with a reason rather than skipped: skipping would
// silently leave a real secret unprotected while reporting the file handled.
// The one exception is an EMPTY flow mapping (`data: {}`) — nothing is
// exposed in it, so refusing would contradict the file being harmless.
func sectionPairs(m *yaml.Node) ([]k8sPair, string) {
	if m == nil {
		return nil, ""
	}
	if m.Kind == yaml.MappingNode && m.Style == yaml.FlowStyle && len(m.Content) == 0 {
		return nil, ""
	}
	if m.Kind != yaml.MappingNode || m.Style == yaml.FlowStyle {
		return nil, "a data:/stringData: section is not a plain block mapping"
	}
	var pairs []k8sPair
	for i := 0; i+1 < len(m.Content); i += 2 {
		pairs = append(pairs, k8sPair{key: m.Content[i], value: m.Content[i+1]})
	}
	return pairs, ""
}

// k8sPlaceholderValue matches a value that IS a template placeholder rather
// than a secret: a whole-value `${VAR}`, `$(VAR)` or `{{ ... }}`. Vaulting
// one would freeze the placeholder text as the "secret" and silently break
// the envsubst/Helm pipeline that expected to fill it in — found by
// adversarial QA (a chart value `{{ .Values.extraSecret }}` got vaulted and
// served back base64-encoded). Left verbatim in the template instead.
var k8sPlaceholderValue = regexp.MustCompile(`^(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\([A-Za-z_][A-Za-z0-9_]*\)|\{\{.*\}\})$`)

// plaintextK8sValues filters a section's pairs down to the ones holding an
// exposed value worth moving, and counts the "inert" skips (empty, masked,
// whole-value template placeholders) separately from ENC[...] values so the
// caller can tell "nothing was plaintext" apart from "already encrypted".
// Whatever is skipped stays verbatim in the template.
func plaintextK8sValues(pairs []k8sPair) (out []k8sPair, inert int) {
	for _, kv := range pairs {
		val := strings.TrimSpace(kv.value.Value)
		if val == "" || audit.IsAlreadyMasked(val) || k8sPlaceholderValue.MatchString(val) {
			inert++
			continue
		}
		if strings.HasPrefix(kv.value.Value, "ENC[") {
			continue
		}
		out = append(out, kv)
	}
	return out, inert
}
