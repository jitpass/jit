// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/user"
	"runtime"
	"time"
)

// SchemaVersion is the NDJSON record schema version (RFC.md §4) — versioned
// independently from ScannerVersion, which tracks the jit binary itself.
// 0.2.0 added scan_summary's jit_protected_count (additive, so a minor bump).
// 0.3.0 added the wrappable_cli_token finding type and its
// findings_by_category key (additive).
// 0.4.0 added scan_summary's exposure_score (additive).
// 0.5.0 added scan_summary's synthetic_finding_count and
// synthetic_playground_paths (additive): findings living inside a jitpass
// playground checkout crossed during a machine-wide walk, excluded from the
// score so synthetic bait never inflates a real machine's risk.
// 0.6.0 added the sops_age_key finding type and its findings_by_category
// key (additive, same shape as 0.3.0's wrappable_cli_token bump).
// 0.7.0 added the finding's archived flag (additive): true when the file
// lives under an archived/backup-looking directory, which `jit migrate
// home` skips by default (--include-archived includes them).
// 0.8.0 removed scan_summary's synthetic_finding_count and
// synthetic_playground_paths along with the jitpass playground feature they
// described (0.5.0); consumers that read them should treat them as absent.
// 0.9.0 added the exposed_secret finding type and its findings_by_category
// key (additive, same shape as 0.3.0/0.6.0's type bumps): a vendor-token or
// JWT match found by content in a file the user named explicitly to `jit
// scan <path>`, independent of the file's name or location.
// 0.10.0 removed the suspicious_filename finding type and its
// findings_by_category key, along with the name-only scanner behind it (the
// same shape of removal as 0.8.0); consumers that read that key should treat
// it as absent. The category cost a full extra home-directory walk plus an
// open of every file on the machine — its jit-pointer exemption ran before
// any name rule matched — to produce name-only, judgment-call findings, and
// its .env.bak rule duplicated what ScanEnvFiles already reports, since
// envFileNamePattern matches ".env.bak" like any other .env-family suffix.
// 0.11.0 added scan_summary's unfiltered flag (additive): true when the run
// was made with `jit scan --unfiltered`, which turns off the name/value
// suppression gates. Without it a saved report is ambiguous — a deliberately
// noisy audit run and a normal risk assessment are byte-indistinguishable,
// and consumers cannot tell which they are looking at. The same bump records
// a semantic change consumers should know about: exposed_secret findings are
// no longer produced only by a targeted `jit scan <path>` (as 0.9.0 stated).
// A machine-wide walk now emits them too, for files whose NAME says they hold
// credentials (see classifyCredentialDump) — the finding still requires a
// vendor-format match in the content, so its meaning is unchanged, only its
// provenance is wider.
// 0.12.0 added three additive finding fields and four scan_summary fields for
// the coverage/triage report. Per finding: `remedy` ("migrate" | "wrap" |
// "manual") says who can act — jit or only the user; `fix_command` is the
// exact runnable command when remedy is jit's (absent for manual);
// `cause_group` is an opaque id shared by findings that describe the same
// underlying secret (the same value re-found in copies of a file), so
// consumers can collapse duplicates the way the human report does. Per
// scan_summary: `secrets_total` / `secrets_protected` / `secrets_migratable`
// count DISTINCT secrets (not findings — 13 copies of one dump are 3 secrets),
// and `files_scanned` records the walk's size. Distinct-secret counts include
// only Critical/High/Medium findings; Low/Info sightings are deliberately not
// counted as secrets (see CountedAsSecret).
const SchemaVersion = "0.12.0"

// ScannerName identifies this tool in the shared NDJSON envelope, matching
// bumblebee's record shape so a receiver can co-ingest both (RFC.md §4).
const ScannerName = "jit"

// Record types (envelope "record_type").
const (
	RecordTypeFinding     = "finding"
	RecordTypeScanSummary = "scan_summary"
)

// Finding types — one per RFC.md §4 scan category. These are enum labels
// naming a finding *type*, not credential material, despite containing words
// like "secret"/"credential" — gosec's G101 heuristic flags them anyway
// (pattern-matches on identifier names, not actual values), hence the
// per-line suppressions below rather than diverging from RFC.md's own
// terminology.
const (
	FindingTypeShellConfigSecret = "shell_config_secret" // #nosec G101 -- enum label, not a credential
	FindingTypeEnvFilePresent    = "env_file_present"
	FindingTypeCredentialFile    = "credential_file"     // #nosec G101 -- enum label, not a credential
	FindingTypeMCPEmbeddedSecret = "mcp_embedded_secret" // #nosec G101 -- enum label, not a credential
	FindingTypePrivateKeyRisk    = "private_key_risk"
	FindingTypeIACVariableFile   = "iac_variable_file"
	FindingTypeWrappableCLIToken = "wrappable_cli_token" // #nosec G101 -- enum label, not a credential
	FindingTypeSOPSAgeKey        = "sops_age_key"        // #nosec G101 -- enum label, not a credential
	FindingTypeExposedSecret     = "exposed_secret"      // #nosec G101 -- enum label, not a credential
)

// AllFindingTypes lists every finding_type in the fixed order used for
// scan_summary's findings_by_category map (RFC.md §4's original seven
// categories, less suspicious_filename which schema 0.10.0 removed — plus
// wrappable_cli_token, added in schema 0.3.0; every key is always present
// either way).
var AllFindingTypes = []string{
	FindingTypeShellConfigSecret,
	FindingTypeEnvFilePresent,
	FindingTypeCredentialFile,
	FindingTypeMCPEmbeddedSecret,
	FindingTypePrivateKeyRisk,
	FindingTypeIACVariableFile,
	FindingTypeWrappableCLIToken,
	FindingTypeSOPSAgeKey,
	FindingTypeExposedSecret,
}

// Severity levels for an individual finding.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Risk levels for an aggregate scan_summary.
const (
	RiskLevelCritical = "critical"
	RiskLevelHigh     = "high"
	RiskLevelMedium   = "medium"
	RiskLevelLow      = "low"
	RiskLevelClean    = "clean"
)

// Confidence levels for an individual finding.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Endpoint identifies the machine a scan ran on. Shape is identical to
// bumblebee's endpoint block (RFC.md §4) for co-ingestion. DeviceID is always
// "" in Phase 1 — there is no MDM integration for an individual-developer OSS
// tool (Phase 1 scope).
type Endpoint struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Username string `json:"username"`
	UID      string `json:"uid"`
	DeviceID string `json:"device_id"`
}

// CurrentEndpoint populates an Endpoint describing the machine this process
// is running on.
func CurrentEndpoint() Endpoint {
	hostname, _ := os.Hostname()
	username := ""
	uid := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
		uid = u.Uid
	}
	return Endpoint{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Username: username,
		UID:      uid,
		DeviceID: "",
	}
}

// Finding is one "finding" NDJSON record (RFC.md §4). Line, KeyName,
// ValuePreview, and PublicIPMatch are pointers so they serialize as JSON
// null when not applicable, matching the documented schema exactly.
type Finding struct {
	RecordType     string   `json:"record_type"`
	RecordID       string   `json:"record_id"`
	SchemaVersion  string   `json:"schema_version"`
	ScannerName    string   `json:"scanner_name"`
	ScannerVersion string   `json:"scanner_version"`
	RunID          string   `json:"run_id"`
	ScanTime       string   `json:"scan_time"`
	Endpoint       Endpoint `json:"endpoint"`

	FindingType              string  `json:"finding_type"`
	Severity                 string  `json:"severity"`
	FilePath                 string  `json:"file_path"`
	Line                     *int    `json:"line"`
	KeyName                  *string `json:"key_name"`
	ValuePreview             *string `json:"value_preview"`
	ProductionIndicatorMatch bool    `json:"production_indicator_match"`
	PublicIPMatch            *string `json:"public_ip_match"`
	Confidence               string  `json:"confidence"`
	Evidence                 string  `json:"evidence"`
	AlreadyMasked            bool    `json:"already_masked"`
	// Archived is true when FilePath sits under an archived/backup-looking
	// directory (LooksArchived) — the same test `jit migrate home` uses to
	// skip a finding unless --include-archived, so a consumer (or the
	// report renderers) can tell "migrate will skip this one" apart from
	// an ordinary actionable finding. Set centrally by Scan, not by the
	// individual scanners.
	Archived bool `json:"archived"`

	// Remedy says who can act on this finding: "migrate" and "wrap" mean jit
	// can (FixCommand holds the exact command), "manual" means only the user
	// can (rotate, delete, seal — the Evidence says which). Set centrally by
	// Scan (annotateRemedies), except wrappable findings, whose scanner knows
	// the tool name and sets both fields at construction.
	Remedy     string `json:"remedy"`
	FixCommand string `json:"fix_command,omitempty"`
	// CauseGroup is an opaque id shared by findings describing the same
	// underlying secret — the same value re-found in several files. Stable
	// within one run only (it is salted per run; see annotateCauseGroups).
	// Empty for findings with no value (a file-presence finding is its own
	// cause). Consumers can collapse on it the way the human report does.
	CauseGroup string `json:"cause_group,omitempty"`

	// rawValueDigest is sha256(raw value), hex — the identity
	// annotateCauseGroups groups on. Unexported and never serialized: it
	// exists so two different AWS keys (identical 4-char previews) stay two
	// secrets, without retaining or ever emitting the raw value.
	rawValueDigest string

	// ClaimedValuePreviews lists MaskValue previews of values this finding's
	// scanner PARSED but deliberately did not report — the non-secret half of
	// a credential pair (an AWS access key ID next to its reported secret),
	// or a value whose reporting the scanner declined on purpose (mcp-remote's
	// short-lived access token next to its reported refresh token).
	//
	// In-process only, never serialized: dropRedundantExposedSecrets uses it
	// to tell "the content sweep re-found a value this file's scanner already
	// judged" (redundant, dropped) from "the sweep found a value the scanner
	// never saw" (a foreign token pasted into a claimed file — a real finding
	// that must survive).
	ClaimedValuePreviews []string `json:"-"`
}

// ScanSummary is the single closing "scan_summary" NDJSON record for a run
// (RFC.md §4).
type ScanSummary struct {
	RecordType     string   `json:"record_type"`
	RecordID       *string  `json:"record_id"` // always null — run_id is already unique per run
	SchemaVersion  string   `json:"schema_version"`
	ScannerName    string   `json:"scanner_name"`
	ScannerVersion string   `json:"scanner_version"`
	RunID          string   `json:"run_id"`
	ScanTime       string   `json:"scan_time"`
	Endpoint       Endpoint `json:"endpoint"`

	TotalFindings            int            `json:"total_findings"`
	FindingsByCategory       map[string]int `json:"findings_by_category"`
	RiskLevel                string         `json:"risk_level"`
	ExposureScore            int            `json:"exposure_score"` // 0..100, see ComputeExposureScore
	ProductionIndicatorCount int            `json:"production_indicator_count"`
	PublicIPCount            int            `json:"public_ip_count"`
	ScanDurationMs           int64          `json:"scan_duration_ms"`
	// Unfiltered records that Config.Unfiltered was set for this run, so a
	// stored report says which view it is. See Config.Unfiltered.
	Unfiltered bool `json:"unfiltered"`
	// The coverage ledger, in DISTINCT secrets (not findings; see
	// SchemaVersion 0.12.0 note): how many secrets exist on this machine as
	// far as jit can tell (protected + counted exposed), how many are already
	// served from the vault by live mounts, and how many of the exposed ones
	// jit can protect with a command (remedy != "manual").
	SecretsTotal      int `json:"secrets_total"`
	SecretsProtected  int `json:"secrets_protected"`
	SecretsMigratable int `json:"secrets_migratable"`
	// FilesScanned is how many regular files the machine-wide walk offered to
	// the classifiers (0 for a targeted scan, which walks nothing).
	FilesScanned int `json:"files_scanned"`
	// JitProtectedCount is how many registered jit live mounts (FIFOs
	// currently occupying a path jit migrated) exist on this machine.
	// Scanners never read those paths — a pipe has no at-rest content, and
	// what the agent serves through it is decoy values, not an exposure —
	// so this count is what keeps the skip visible instead of silent: the
	// files ARE there, they're just already protected.
	JitProtectedCount int `json:"jit_protected_count"`
}

// Config carries per-run context shared by every category scanner: where to
// look (HomeDir is overridable so tests never touch the real home directory)
// and the envelope fields every record in this run shares.
type Config struct {
	HomeDir        string
	RunID          string
	ScannerVersion string
	Endpoint       Endpoint
	// MountRegistryPath is jit's own mounts.yaml (read-only here, like
	// everything else this package touches) — used ONLY to count currently
	// live mounts for ScanSummary.JitProtectedCount, never to decide what
	// gets scanned (that's walkHomeDir's regular-file guard, which needs no
	// registry: a named pipe has no at-rest content whether jit made it or
	// not). Empty (the default in tests) means no count is reported.
	MountRegistryPath string

	// Unfiltered turns OFF the name/value suppression gates
	// (LooksLikeNonSecretName, LooksLikeNonSecretValue, and the
	// documented-public JWT rule), so the report shows every secret-shaped
	// finding jit would otherwise judge to be a setting, a path, a
	// browser-public build variable or unfilled template filler.
	//
	// It exists because that filtering is normally INVISIBLE: without it a
	// reader cannot tell "jit found nothing" apart from "jit found things and
	// decided not to mention them". Each gate is a judgment call that trades
	// recall for precision and can be wrong for a given setup, so an auditor
	// needs a way to see the unfiltered view and diff the two.
	//
	// Deliberately does NOT disable isPlaceholderToken's rejection of filler
	// token bodies ("ghp_xxxxxxxx…", "hf_FIXTUREtoken…"). That check lives in
	// MatchKnownTokenPattern, which `jit migrate` shares — migrate must never
	// vault a placeholder as though it were a credential, so the two would
	// disagree about what is real. Value-level filler stays suppressed.
	Unfiltered bool

	// Progress, when non-nil, is called once as each category (or targeted
	// path) is about to be scanned, with a short human noun for it
	// ("credential files", ".env files", or a target's base name). It's a
	// UI-agnostic hook — this package emits the category name and never
	// touches the terminal — so the CLI can render a live status trail while
	// a full home-directory scan runs. nil (the default, and in every test)
	// means no reporting and identical behavior.
	Progress func(category string)
}

// NewConfig builds a Config for a real run against the actual machine.
// Tests should construct Config{} literals directly with a fixture HomeDir
// instead of calling this.
func NewConfig(scannerVersion string) (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}
	return Config{
		HomeDir:        home,
		RunID:          newRunID(),
		ScannerVersion: scannerVersion,
		Endpoint:       CurrentEndpoint(),
	}, nil
}

func newRunID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read only errors if the OS RNG is broken; nothing sane to do but proceed
	return hex.EncodeToString(b)
}

// baseFinding returns a Finding with every envelope field filled in, ready
// for a scanner to set FindingType/FilePath/Severity/etc. and compute
// RecordID before appending it.
func (c Config) baseFinding() Finding {
	return Finding{
		RecordType:     RecordTypeFinding,
		SchemaVersion:  SchemaVersion,
		ScannerName:    ScannerName,
		ScannerVersion: c.ScannerVersion,
		RunID:          c.RunID,
		ScanTime:       nowISO8601(),
		Endpoint:       c.Endpoint,
	}
}

// RecordID computes the content-addressed hash RFC.md §4 specifies:
// "hash of (finding_type, file_path, key_name). Stable across runs, so
// re-scans dedupe cleanly." keyName may be nil (e.g. file-level findings).
func RecordID(findingType, filePath string, keyName *string) string {
	key := ""
	if keyName != nil {
		key = *keyName
	}
	sum := sha256.Sum256([]byte(findingType + "\x00" + filePath + "\x00" + key))
	return "finding:" + hex.EncodeToString(sum[:])[:16]
}

func nowISO8601() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// suppressName / suppressValue are the single gate every scanner asks before
// dropping a secret-shaped finding, so Config.Unfiltered has one place to
// switch off rather than a bool threaded through each call site.
func (c Config) suppressName(key string) bool {
	return !c.Unfiltered && LooksLikeNonSecretName(key)
}

func (c Config) suppressValue(value string) bool {
	return !c.Unfiltered && LooksLikeNonSecretValue(value)
}
