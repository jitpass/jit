// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// maxDecodedSecretValueBytes caps how much of a single data: value we
// base64-decode for signal inspection. Secrets max out at 1MiB cluster-side,
// but a TLS bundle or embedded keystore can still be large, and the
// escalation signals only ever match short human-scale strings — decoding
// megabytes buys nothing but scan time (jit scan advertises ~340ms).
const maxDecodedSecretValueBytes = 64 * 1024

// ScanIACFiles implements RFC.md §4 category 6: IaC variable files.
// Covers Terraform's terraform.tfvars/*.auto.tfvars convention and
// Kubernetes/Helm-style Secret manifests — the latter added after
// real-world review (2026-07-06, see ROADMAP.md) showed it's far more
// common in practice than .tfvars alone. The Terraform half now has an
// automated fix (jit migrate's tfvars category, internal/migrate/
// tfvars.go) and its advisory says so; the Kubernetes half stays
// detection-only, since that file's consumer is a cluster or CI pipeline
// no local rewrite can serve.
//
// The Kubernetes half parses the manifest properly (2026-07-18) instead of
// line-scanning it, because the two behave completely differently under the
// cross-cutting escalation signals: data: values are base64, so a
// production database URL in the common form never matched
// IsProductionIndicator/MatchPublicIP and the finding sat at Info forever.
// Base64 "obscures but does NOT provide any useful level of
// confidentiality" (the Kubernetes docs' own words) — so we decode before
// judging, exactly like an attacker would.
func ScanIACFiles(cfg Config) ([]Finding, error) {
	var findings []Finding
	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		findings = append(findings, classifyIACFile(cfg, path, d.Name())...)
		return nil
	})
	return findings, err
}

// classifyIACFile is the per-file half of ScanIACFiles, split out so `jit scan
// <path>`'s targeted walk applies the identical tfvars / *secret*.y(a)ml name
// gates and structured-content checks a machine-wide walk does. An unreadable
// or unparseable file yields no findings (skip, never fail) — matching the
// walk closure it was extracted from.
func classifyIACFile(cfg Config, path, fileName string) []Finding {
	isTFVars, isK8sCandidate := iacNameGates(fileName)
	var findings []Finding
	switch {
	case isTFVars:
		f, err := buildTfvarsFinding(cfg, path)
		if err != nil {
			return nil // unreadable file — skip it, don't fail the whole audit
		}
		findings = append(findings, f)
	case isK8sCandidate:
		insp, flagged, err := inspectK8sSecretFile(path)
		if err != nil {
			// Not YAML we can parse. Fall back to the pre-2026-07-18
			// substring + line-scan behavior so a hand-mangled but real
			// Secret manifest still gets flagged rather than silently
			// dropped.
			confirmed, cerr := fileContainsSubstring(path, "kind: Secret")
			if cerr != nil || !confirmed {
				return nil
			}
			f, ferr := buildLegacyK8sFinding(cfg, path)
			if ferr != nil {
				return nil
			}
			return append(findings, f)
		}
		if !flagged {
			return nil
		}
		findings = append(findings, buildK8sSecretFinding(cfg, path, insp))
	}
	return findings
}

// iacNameGates reports whether fileName is a tfvars file and/or a Kubernetes
// Secret candidate by name only. The *secret*.y(a)ml gate is deliberately
// broad (db-secrets.yaml, prod.secret.yml, …); classifyIACFile's structured
// content check is what actually prevents false positives. Shared so `jit
// scan <path>` can tell "a scanner claims this file type" apart from "this
// file produced no finding" without re-deriving the suffix rules.
func iacNameGates(fileName string) (isTFVars, isK8sCandidate bool) {
	name := strings.ToLower(fileName)
	isTFVars = fileName == "terraform.tfvars" || strings.HasSuffix(fileName, ".auto.tfvars")
	isK8sCandidate = strings.Contains(name, "secret") &&
		(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"))
	return isTFVars, isK8sCandidate
}

func fileContainsSubstring(path, substr string) (bool, error) {
	file, err := openFile(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), substr) {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// k8sSecretDoc is the subset of a Kubernetes Secret manifest the scanner
// inspects. Kind is matched exactly ("Secret"), which also fixes the old
// substring check's false positive on "kind: SealedSecret" — a SealedSecret
// is the protected form and must never be flagged.
type k8sSecretDoc struct {
	Kind     string `yaml:"kind"`
	Type     string `yaml:"type"`
	Metadata struct {
		UID             string `yaml:"uid"`
		ResourceVersion string `yaml:"resourceVersion"`
	} `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
	// Sops is the metadata block the sops tool appends to files it
	// encrypts. Its presence plus all-ENC[ values means "already
	// protected"; its presence with plaintext values left over means a
	// partial encryption worth calling out.
	Sops map[string]interface{} `yaml:"sops"`
}

// k8sSecretInspection aggregates what inspectK8sSecretFile saw across every
// Secret document in a (possibly multi-document) manifest file.
type k8sSecretInspection struct {
	prodMatch     bool
	ipMatch       bool
	publicIP      string
	exported      bool   // metadata.uid/resourceVersion present: came out of a live cluster
	secretType    string // first non-Opaque built-in type seen, for the severity ladder
	partiallySops bool   // sops metadata present but some values still plaintext
}

// inspectK8sSecretFile parses a candidate manifest and reports whether it
// contains at least one Kubernetes Secret document with unprotected values.
// flagged == false means "leave this file alone": no Secret docs, only
// SOPS-protected docs, or only empty scaffolds. A returned error means the
// file isn't parseable as YAML at all (caller falls back to the legacy
// line scan).
func inspectK8sSecretFile(path string) (k8sSecretInspection, bool, error) {
	file, err := openFile(path)
	if err != nil {
		return k8sSecretInspection{}, false, err
	}
	defer file.Close()

	var insp k8sSecretInspection
	flagged := false

	dec := yaml.NewDecoder(file)
	sawDoc := false
	for {
		// Decode into a Node first, then into the typed struct: a
		// per-document type mismatch (a doc that's a list, a bare scalar)
		// then skips just that document instead of aborting the decoder
		// mid-stream and losing the Secret doc that follows it.
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if !sawDoc {
				return k8sSecretInspection{}, false, err
			}
			break // malformed trailing doc; judge what we already have
		}
		sawDoc = true

		var doc k8sSecretDoc
		if err := node.Decode(&doc); err != nil || doc.Kind != "Secret" {
			continue
		}

		docFlagged, docInsp := inspectSecretDoc(doc)
		if !docFlagged {
			continue
		}
		flagged = true
		insp.prodMatch = insp.prodMatch || docInsp.prodMatch
		insp.exported = insp.exported || docInsp.exported
		insp.partiallySops = insp.partiallySops || docInsp.partiallySops
		if docInsp.ipMatch && !insp.ipMatch {
			insp.ipMatch = true
			insp.publicIP = docInsp.publicIP
		}
		if insp.secretType == "" {
			insp.secretType = docInsp.secretType
		}
	}
	if !sawDoc {
		return k8sSecretInspection{}, false, errors.New("no yaml documents")
	}
	return insp, flagged, nil
}

// inspectSecretDoc judges one kind: Secret document. Not flagged: an empty
// scaffold (no data at all — nothing is exposed), or a fully
// SOPS-encrypted doc (every value ENC[...]), which is the outcome we WANT
// users to reach; flagging it would teach them the audit can't tell
// protected from plaintext.
func inspectSecretDoc(doc k8sSecretDoc) (bool, k8sSecretInspection) {
	var insp k8sSecretInspection

	total := len(doc.Data) + len(doc.StringData)
	if total == 0 {
		return false, insp
	}

	encrypted := 0
	inspectValue := func(raw string, decode bool) {
		if strings.HasPrefix(raw, "ENC[") {
			encrypted++
			return
		}
		if IsAlreadyMasked(strings.TrimSpace(raw)) {
			return
		}
		value := raw
		if decode {
			decoded, ok := decodeSecretDataValue(raw)
			if !ok {
				return // binary or oversized — signals only match human-scale text
			}
			value = decoded
		}
		if IsProductionIndicator(value) {
			insp.prodMatch = true
		}
		if ip, ok := MatchPublicIP(value); ok && !insp.ipMatch {
			insp.ipMatch = true
			insp.publicIP = ip
		}
	}
	for _, v := range doc.Data {
		inspectValue(v, true)
	}
	for _, v := range doc.StringData {
		inspectValue(v, false)
	}

	if encrypted == total {
		return false, insp // fully SOPS-encrypted: already protected
	}
	if doc.Sops != nil || encrypted > 0 {
		insp.partiallySops = true
	}

	insp.exported = doc.Metadata.UID != "" || doc.Metadata.ResourceVersion != ""

	switch doc.Type {
	case "kubernetes.io/tls", "kubernetes.io/ssh-auth",
		"kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg",
		"kubernetes.io/basic-auth":
		insp.secretType = doc.Type
	}

	return true, insp
}

// decodeSecretDataValue base64-decodes one data: value for signal
// inspection. YAML block scalars legally spread the base64 across lines, so
// interior whitespace is stripped first. Returns ok == false for values too
// large to be worth decoding or whose decoded bytes aren't text.
func decodeSecretDataValue(raw string) (string, bool) {
	if len(raw) > maxDecodedSecretValueBytes*4/3 {
		return "", false
	}
	compact := strings.Join(strings.Fields(raw), "")
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		// Not valid base64 — kubectl would reject it, but whatever it is,
		// it's visible plaintext, so judge it as-is.
		return raw, true
	}
	if !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

// buildK8sSecretFinding turns an inspection into the file-level finding.
// Evidence order mirrors severity: an exported live credential outranks a
// decoded signal match, which outranks what the declared type implies.
func buildK8sSecretFinding(cfg Config, path string, insp k8sSecretInspection) Finding {
	f := cfg.baseFinding()
	f.FindingType = FindingTypeIACVariableFile
	f.FilePath = path
	f.Confidence = ConfidenceHigh // structured parse, not a name heuristic
	f.ProductionIndicatorMatch = insp.prodMatch
	if insp.ipMatch {
		ip := insp.publicIP
		f.PublicIPMatch = &ip
	}

	switch {
	case insp.exported:
		f.Severity = SeverityCritical
		f.Evidence = "kubernetes Secret exported from a live cluster (metadata.uid/resourceVersion present): holds live credential values"
	case insp.prodMatch:
		f.Severity = SeverityCritical
		f.Evidence = "kubernetes Secret manifest: a base64-decoded value matches the production-indicator pattern"
	case insp.ipMatch:
		f.Severity = SeverityCritical
		f.Evidence = "kubernetes Secret manifest: a base64-decoded value contains a public IP address"
	case insp.secretType != "":
		f.Severity = SeverityHigh
		f.Evidence = "kubernetes Secret manifest of type " + insp.secretType + ": " + secretTypeRisk(insp.secretType)
	case insp.partiallySops:
		f.Severity = SeverityHigh
		f.Evidence = "kubernetes Secret manifest only partially SOPS-encrypted: some values are still plaintext"
	default:
		f.Severity = SeverityInfo
		f.Evidence = "kubernetes Secret manifest (base64 is encoding, not encryption): detection only, no automated fix yet"
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return f
}

// secretTypeRisk translates a built-in Secret type into what is actually
// sitting on disk, so the report says "private key" instead of making the
// reader look the type string up.
func secretTypeRisk(secretType string) string {
	switch secretType {
	case "kubernetes.io/tls":
		return "holds a TLS private key"
	case "kubernetes.io/ssh-auth":
		return "holds an SSH private key"
	case "kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg":
		return "holds container registry credentials"
	case "kubernetes.io/basic-auth":
		return "holds a username/password pair"
	}
	return "holds credential material"
}

// buildTfvarsFinding is the original line-scan path, now Terraform-only:
// tfvars values are plaintext HCL, so raw-line signal matching is correct
// there in a way it never was for base64 Secret data.
func buildTfvarsFinding(cfg Config, path string) (Finding, error) {
	prodMatch, ipMatch, publicIP, err := scanLinesForSignals(path)
	if err != nil {
		return Finding{}, err
	}

	f := cfg.baseFinding()
	f.FindingType = FindingTypeIACVariableFile
	f.FilePath = path
	f.Confidence = ConfidenceMedium
	f.ProductionIndicatorMatch = prodMatch
	if ipMatch {
		f.PublicIPMatch = &publicIP
	}

	switch {
	case prodMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a value matching the production-indicator pattern"
	case ipMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a public IP address in a visible value"
	default:
		f.Severity = SeverityInfo
		f.Evidence = "terraform variable file: `jit migrate` can move its secret values into the vault"
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return f, nil
}

// buildLegacyK8sFinding is the pre-structured-parse fallback for a file
// that contains "kind: Secret" but isn't valid YAML: keep the old
// line-scan behavior so it degrades to exactly what shipped before, never
// to silence.
func buildLegacyK8sFinding(cfg Config, path string) (Finding, error) {
	prodMatch, ipMatch, publicIP, err := scanLinesForSignals(path)
	if err != nil {
		return Finding{}, err
	}

	f := cfg.baseFinding()
	f.FindingType = FindingTypeIACVariableFile
	f.FilePath = path
	f.Confidence = ConfidenceMedium
	f.ProductionIndicatorMatch = prodMatch
	if ipMatch {
		f.PublicIPMatch = &publicIP
	}

	switch {
	case prodMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a value matching the production-indicator pattern"
	case ipMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a public IP address in a visible value"
	default:
		f.Severity = SeverityInfo
		f.Evidence = "kubernetes Secret manifest (base64 is encoding, not encryption): detection only, no automated fix yet"
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return f, nil
}

func scanLinesForSignals(path string) (prodMatch, ipMatch bool, publicIP string, err error) {
	file, err := openFile(path)
	if err != nil {
		return false, false, "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if IsAlreadyMasked(strings.TrimSpace(line)) {
			continue
		}
		if IsProductionIndicator(line) {
			prodMatch = true
		}
		if ip, ok := MatchPublicIP(line); ok && !ipMatch {
			ipMatch = true
			publicIP = ip
		}
	}
	if err := scanner.Err(); err != nil {
		return false, false, "", err
	}
	return prodMatch, ipMatch, publicIP, nil
}
