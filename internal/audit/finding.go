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
// lives under an archived/backup-looking directory, which the `jit migrate`
// sweep walks past. (This read "--include-archived includes them" until
// 2026-08-06; no such flag was ever built. Naming the path explicitly is
// what reaches them: `jit migrate <path>`.)
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
// 0.13.0 added one additive finding field, `test_fixture`: the file is test
// scaffolding (a *_test.go, something under testdata/ — see LooksTestFixture),
// so the match is a real credential format written to exercise a parser rather
// than a credential anyone owns. Such findings are still emitted in full; what
// changes is that they no longer count toward the distinct-secret ledger, for
// the same reason Low/Info sightings do not — a score the user cannot move by
// doing anything real is not a score worth printing.
// 0.14.0 added one additive SUMMARY field, `degraded_scanners`: the categories
// that could not complete this run, with their reasons. Before it, a single
// unreadable fixed-path file (a root-owned ~/.aws/credentials left by a sudo
// run) aborted the entire scan, so nothing was reported anywhere; now the rest
// of the scan finishes and this field is what keeps the gap from reading as an
// all-clear. Absent on a clean run.
// 0.15.0 added two additive finding fields, `unfiltered_only` and
// `unfiltered_reason`: set only under Config.Unfiltered, on findings the
// everyday scan's suppression gates would have dropped (or reported at a
// lower severity), with the reason naming the gate rule that fired. Before
// them an unfiltered report was indistinguishable from a normal one
// finding-by-finding, which defeated the flag's stated purpose of auditing
// what the filters hide. Absent (false/"") on every normal run.
// 0.16.0 added the shell_history_secret finding type and its
// findings_by_category key (additive, same shape as 0.3.0/0.6.0/0.9.0's type
// bumps): a vendor-format credential recorded in a shell history file
// (~/.zsh_history, ~/.bash_history, $HISTFILE, fish). The same bump records a
// semantic note for consumers computing their own coverage: an ordinary
// history finding carries remedy "migrate" (`jit migrate <historyfile>`
// redacts each occurrence in place and vaults the value), but one flagged
// with a production indicator carries remedy "manual" — and a cause_group
// with a MANUAL history finding in it is never counted in
// secrets_migratable, even when another finding in the same group carries
// remedy "migrate". That history line is a live plaintext copy the
// recommended command will not touch, so protecting the other copy does not
// protect the secret (see ComputeCoverage).
//
// The same bump changes cause_group IDENTITY for every finding type, not just
// the new one: the group id is now the digest of the full value alone, where
// it previously mixed in key_name (see annotateCauseGroups for why — one
// token under two scanners' names was scoring as two secrets). Group ids were
// already documented as stable only within a run, so nothing is broken, but a
// consumer diffing groups across versions will see every id move rather than
// only the history ones.
// 0.17.0 changes WHERE mcp_embedded_secret findings come from, without
// changing the record shape. The MCP scanner used to read a server entry's
// env block and nothing else; it now also reports a credential passed by
// `--env-file`, one baked into `args` (including `docker run -e`), and a
// remote server's `headers` or `url`. ~/.claude.json (Claude Code's own
// store, including its nested projects.<dir>.mcpServers) is a new source of
// findings entirely. No field was added or removed, but a consumer will see
// this finding type in situations it never appeared in before, which is the
// same kind of change 0.11.0 recorded for exposed_secret.
//
// Two shapes worth knowing for anything parsing key_name: the args/headers/
// url findings spell it "<server>/args[2]", "<server>/header:Authorization"
// and "<server>/url", and the --env-file finding carries the bare server
// name with the file named in `evidence`. The three jit cannot fix (args,
// headers, url) carry remedy "manual" — the MCP host makes that request or
// builds that command line itself, so there is nothing for jit to inject
// into.
//
// The same bump lowers severity on one existing shape: a short, low-entropy
// plain setting in an env block ("CRAWL4AI_LANG=en") now reports Low rather
// than High. Everything in an env block is credential-shaped by construction
// only when a human wrote the file; ~/.claude.json is written by a tool and
// carries ordinary settings in the same block. Production-indicator and
// public-IP escalations still override it.
// 0.18.0 adds finding type agent_cached_secret: a verbatim copy of a
// credential, found in an AI coding agent's local cache (Claude Code's
// file-history and paste-cache, agent transcripts, and the equivalent
// directories for other agents).
//
// It is the first finding type produced by CORROBORATION rather than
// detection. Every other type answers "does this file contain something
// credential-shaped"; this one answers "is a secret I already confirmed
// elsewhere in this same run also sitting here, byte for byte". A consumer
// should read it accordingly: there is no pattern behind it and no
// confidence judgment to second-guess, but it can never appear alone —
// it always shares a cause_group with the finding that identified the
// value, and that sibling names the credential's real home.
//
// Two consequences worth knowing. The finding does not add a secret to the
// ledger: it is the same secret in another place, so coverage counts it
// once through the shared cause_group. And it carries remedy "manual"
// today, which makes its whole cause group non-migratable — `jit migrate`
// rewrites the file the credential lives in and does not yet clean these
// copies, so claiming otherwise would promise a coverage gain the
// recommended command does not deliver (the rule shell_history_secret
// already follows for its production case).
// 0.19.0 adds one additive finding field and records two semantic changes to
// the coverage ledger.
//
// Two fields, both about making the ledger auditable from the stream.
//
// `source_example`: the vendor match sits on a comment line of a source-code
// file, so it documents a shape rather than storing a credential. It has
// always existed in-process and has always been one of the exclusions behind
// secrets_total — it simply was not serialized, which left a consumer unable
// to reproduce the ledger. The gap was known and documented rather than
// closed.
//
// `origin_path`: the file a finding's credential actually lives in, when the
// finding is not that file (an agent's cached copy, an MCP config's
// --env-file link). A path, never a value, and evidence already named it in
// prose. Without it a consumer could not apply the rule the tally applies and
// counted every link as its own secret.
//
// What a consumer can now reproduce: exclude test_fixture, source_example and
// low/info severities; drop agent_cached_secret; drop any finding whose
// origin_path names a file that itself carries a counted finding; then count
// distinct cause_group (falling back to record_id when empty).
//
// What still will NOT reconcile, and why: one further dedupe compares RAW
// VALUES a file-level scanner parsed but reported only at file level — the
// .env that "claims" a credential the content sweep then re-finds in a paste
// cache. Reproducing it needs the values themselves, and those are
// deliberately never serialized (Finding.rawValue's contract). On the machine
// this bump was measured against it accounts for a difference of one. A
// consumer recomputing coverage should therefore expect to land at or
// slightly above secrets_total, never below.
//
// First semantic change: an mcp_embedded_secret produced by a server's
// `--env-file` pointer no longer adds to secrets_total WHEN the file it names
// carries a counted finding of its own. That finding is a link — it says
// which server consumes a flagged credential file — and the credential is
// counted where it lives. It was tallied as a second secret, so a config
// naming a reported .env scored two for one credential (measured 2026-08-09).
// A pointer at a target the .env name gate drops is still counted, which is
// the first-sight coverage the finding was added for; nothing becomes
// invisible.
//
// Second semantic change: a terraform.tfvars holding no production indicator,
// no public IP, no vendor-format value and no secret-shaped name now carries
// remedy "manual" with no fix_command, and evidence that describes the file
// instead of promising a migration. It previously carried remedy "migrate"
// and a runnable fix_command that answered "Nothing to migrate" on the very
// path it named.
const SchemaVersion = "0.19.0"

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
	// A credential typed at the shell and recorded in a history file. Fixed by
	// `jit migrate <historyfile>`, which vaults the value and redacts every
	// occurrence in place — except when the credential carries a production
	// indicator, where rotation is the remedy and no command substitutes for
	// it. See annotateRemedies.
	FindingTypeShellHistorySecret = "shell_history_secret" // #nosec G101 -- enum label, not a credential
	// A verbatim copy of a credential jit found elsewhere on this machine,
	// sitting in an AI coding agent's local cache — a transcript, a pasted
	// blob, or the agent's own copy of a file it edited. Never discovered by
	// pattern: this finding exists only because the SAME value was confirmed
	// in a structured store in the same run, which is what makes it a fact
	// rather than a guess. See agentcache.go.
	FindingTypeAgentCachedSecret = "agent_cached_secret" // #nosec G101 -- enum label, not a credential
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
	FindingTypeShellHistorySecret,
	FindingTypeAgentCachedSecret,
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

	FindingType string  `json:"finding_type"`
	Severity    string  `json:"severity"`
	FilePath    string  `json:"file_path"`
	Line        *int    `json:"line"`
	KeyName     *string `json:"key_name"`
	// EndLine closes a finding that spans lines — today only a PEM key block
	// pasted into shell history, where Line alone names the header and leaves
	// the reader guessing how far the block runs.
	//
	// Deliberately NOT serialized. The NDJSON envelope is the documented
	// schema in RFC.md §4, and adding a field to it is a schema version bump
	// and a contract with every consumer; this exists to let the human-facing
	// report print a range it already knows. Give it a json tag and a version
	// when a consumer actually asks for it, not before.
	EndLine *int `json:"-"`
	// KeyKind says WHAT kind of key a private-key finding covers, when the
	// sniffer can tell — today only the GCP service-account JSON shape. The
	// advice attached to the finding depends on it: "add a passphrase" is
	// impossible to follow for a service-account key, which can only be
	// revoked where it was issued. Empty means "an SSH-shaped key", the
	// default the advice was written for.
	//
	// Deliberately NOT serialized, on EndLine's contract: key_name already
	// carries the human name of the kind for NDJSON consumers, so this
	// stays a rendering input until a consumer asks for more.
	KeyKind                  string  `json:"-"`
	ValuePreview             *string `json:"value_preview"`
	ProductionIndicatorMatch bool    `json:"production_indicator_match"`
	PublicIPMatch            *string `json:"public_ip_match"`
	Confidence               string  `json:"confidence"`
	Evidence                 string  `json:"evidence"`
	AlreadyMasked            bool    `json:"already_masked"`
	// Archived is true when FilePath sits under an archived/backup-looking
	// directory (LooksArchived) — the same test `jit migrate ~` uses to
	// skip a finding, so a consumer (or the report renderers) can tell
	// "migrate will skip this one" apart from an ordinary actionable
	// finding. Set centrally by Scan, not by the individual scanners.
	//
	// The skip has no override flag; `jit migrate <path>` is how a caller
	// reaches these deliberately, one project at a time. See
	// internal/migrate's doc.go for why the sweep declines to.
	Archived bool `json:"archived"`

	// TestFixture is true when FilePath is test scaffolding — a *_test.go, a
	// file under testdata/ (LooksTestFixture). The value matched a real
	// credential format, which is exactly what a scanner's own fixtures are
	// written to do; what is missing is an owner. Such a finding is reported
	// and streamed like any other, but is not charged to the coverage ledger
	// (CountedAsSecret), because there is nothing for the user to rotate.
	// Set centrally by Scan, not by the individual scanners.
	TestFixture bool `json:"test_fixture"`

	// SourceExample is true when the matched value sits on a comment line of
	// a source-code file: a documentation example, not a stored credential.
	// The canonical case is jit's own tokenpatterns.go, whose doc comments
	// argue about credential shapes BY EXAMPLE and which a real scan
	// (2026-08-07) reported as an exposed database password — a scanner that
	// flags its own source teaches users to disbelieve the report. Like a
	// fixture, the finding stays visible in --full and NDJSON but is not
	// charged to the coverage ledger. The accepted miss: a commented-out
	// REAL credential in source is indistinguishable from an example and
	// lands here too, which is why the footer names the bucket instead of
	// silently dropping it.
	//
	// Set by the content sweep at construction (it alone has the line text),
	// not by tagArchivedAndFixtures.
	//
	// Serialized since 0.19.0. It was withheld on EndLine's contract ("give
	// it a json tag when a consumer actually asks"), but this field is not a
	// rendering convenience — it is one of the three exclusions that decide
	// secrets_total, and the other two (test_fixture, and severity for the
	// low/info sightings) are both readable from the record. Withholding just
	// this one left the ledger unreproducible from the stream, which
	// docs/reference/scan-ndjson.md documented as a known divergence rather
	// than fixing. test_fixture was serialized in 0.13.0 for exactly this
	// reason; this is its twin.
	SourceExample bool `json:"source_example"`

	// AssignedName is the variable or setting name this credential was
	// assigned to where jit found it, when the line offered one that is
	// unmistakably a label (see assignedCredentialName). It is what tells two
	// findings of the same vendor apart: "An exposed GitHub Fine-Grained
	// Personal Access Token" describes the pattern that matched and reads
	// identically for a live release-publishing token and for a test vector.
	//
	// Deliberately NOT serialized, on EndLine's contract: it is a rendering
	// input the report uses to make a title specific, and no consumer has
	// asked for it. It changes no count, so unlike source_example its absence
	// leaves nothing about the record stream unreproducible.
	AssignedName string `json:"-"`

	// Occurrences is how many times this finding's vendor format appears in
	// this file. One finding covers all of them (record_id is
	// type+path+key_name, so a second would collide), and the reader still
	// needs to know whether the line named below is the only one.
	//
	// Not serialized, on EndLine's contract: a rendering input that changes no
	// count. Zero means "not counted", not "one".
	Occurrences int `json:"-"`

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

	// UnfilteredOnly marks a finding that exists — or carries this severity —
	// only because Config.Unfiltered turned the suppression gates off. The
	// everyday scan either drops it entirely (shell/cred/tfvars name-gated
	// findings) or reports the file without this escalation (a .env whose
	// only secret-shaped names are gate-suppressed). UnfilteredReason is the
	// gate rule that fired, worded by NonSecretNameReason/NonSecretValueReason
	// for the report to print verbatim. Both are zero on every normal run,
	// which is what lets a reader diff the two views inside ONE report
	// instead of running the scan twice.
	UnfilteredOnly   bool   `json:"unfiltered_only,omitempty"`
	UnfilteredReason string `json:"unfiltered_reason,omitempty"`

	// rawValueDigest is sha256(raw value), hex — the identity
	// annotateCauseGroups groups on. Unexported and never serialized: it
	// exists so two different AWS keys (identical 4-char previews) stay two
	// secrets, without retaining or ever emitting the raw value.
	rawValueDigest string

	// rawValue is the credential itself, in the clear, for the length of one
	// scan. It is the needle crossReferenceAgentCaches searches AI agent
	// caches for, and there is no substitute: finding a verbatim copy of a
	// secret requires the secret. A digest cannot search a file it has not
	// already parsed, and parsing 300 MB of agent transcripts with the vendor
	// patterns is the 100-second, 2,000-false-positive path this field exists
	// to avoid (see agentcache.go).
	//
	// Unexported, like rawValueDigest, so encoding/json cannot reach it —
	// that is the whole guarantee, and it is why the field is here rather
	// than in a parallel structure some future caller might marshal. Nothing
	// new reaches memory that was not already there: every scanner reads
	// these values off disk to judge them. What is new is that they outlive
	// their scanner, for the length of the run.
	//
	// Set only on the unmasked path in ValueFinding: an already-masked value
	// ("ghp_****") is not a credential, and searching for it would match the
	// mask rather than the secret.
	rawValue string

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

	// claimedRawValues is ClaimedValuePreviews' unmasked counterpart, under
	// the same never-serialized rule as rawValue: the credentials a scanner
	// parsed and judged real but reported only at FILE level.
	//
	// It exists for one category, and that category is the important one.
	// env_file_present is a single finding per .env — the file is the
	// problem, and listing each variable would report one leak five times —
	// so no per-variable ValueFinding is built and .env files contributed no
	// needle at all to crossReferenceAgentCaches. That left the scanner blind
	// to its own headline case: a live Stripe key in ~/project/.env, copied
	// nine times into an agent's file cache, found by neither half.
	//
	// The variable name rides along because a copy has to be able to say WHAT
	// it is a copy of: "STRIPE_API_KEY, also in Claude Code's file cache" is
	// the finding; the same sentence without the name is a riddle.
	claimedRawValues []claimedValue

	// OriginPath is the file the credential this finding describes actually
	// lives in, when this finding is not that file. It is what lets
	// ComputeCoverage tie a finding back to the secret it stands in for when
	// no cause_group can — a file-level origin (env_file_present) carries no
	// value digest, so anything pointing at it would otherwise look like a
	// brand-new secret and inflate the ledger.
	//
	// Two producers, both meaning "counted elsewhere, not here":
	//   - agent_cached_secret, where it names the file the copy came from;
	//   - mcp_embedded_secret's --env-file link, where it names the
	//     credential file the server reads (scanMCPEnvFilePointers).
	// In both cases the finding is still reported in full; only the tally
	// skips it, and only when the origin is itself counted.
	//
	// Serialized since 0.19.0, and safe to be: it is a path, never a value,
	// and `evidence` already names it in prose for both producers. Without
	// it in the stream a consumer could not apply the rule the ledger
	// applies, so a recomputed total counted every link as its own secret.
	OriginPath string `json:"origin_path,omitempty"`
}

// claimedValue is one credential a file-level scanner parsed and judged real
// without reporting it individually. Never serialized; see
// Finding.claimedRawValues.
type claimedValue struct {
	Key   string
	Value string
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
	// Targets are the paths a targeted `jit scan <path>...` was pointed at,
	// empty for the machine-wide scan. Carried so the report header can say
	// what was actually scanned: it used to print "~/" regardless, so
	// `jit scan token.txt` opened by claiming a whole-home scan had happened —
	// wrong in both directions (overstating what was checked, understating
	// where the findings came from). Additive, so no schema bump (the same
	// rule doctorSchemaVersion states).
	Targets []string `json:"targets,omitempty"`
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
	// DerivedCredentials are the tool-written credential artifacts found
	// alongside this scan (see DerivedCredential). Advisory only: they are
	// never findings, never counted in any total, and never affect the risk
	// level or coverage ledger — jit cannot act on them, and inflating the
	// numbers with things no command can fix would make every other number
	// less useful.
	//
	// In-process only, never serialized: the NDJSON schema describes findings
	// jit stands behind, and this is a note to a human reading the report.
	DerivedCredentials []DerivedCredential `json:"-"`

	// DegradedScanners names every category that could not finish, and why.
	//
	// Serialized, unlike DerivedCredentials, because this one changes what the
	// rest of the record MEANS: a total of zero from a scan with a degraded
	// scanner is "we could not look there", not "there is nothing there", and a
	// machine consumer that cannot tell those apart will read the second when
	// the first is true. Empty (omitted) on a clean run, which is the norm.
	DegradedScanners []ScannerFailure `json:"degraded_scanners,omitempty"`

	// JitProtectedCount is how many registered jit live mounts (FIFOs
	// currently occupying a path jit migrated) exist on this machine.
	// Scanners never read those paths — a pipe has no at-rest content, and
	// what the agent serves through it is decoy values, not an exposure —
	// so this count is what keeps the skip visible instead of silent: the
	// files ARE there, they're just already protected.
	JitProtectedCount int `json:"jit_protected_count"`
}

// ScannerFailure is one category that could not complete, and the reason.
// Scanner is the category's own display name (the same string Config.Progress
// is given), so a user can match it against the trail of what was looked at.
type ScannerFailure struct {
	Scanner string `json:"scanner"`
	Error   string `json:"error"`
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

// nameGate / valueGate are the single gate every scanner asks before
// dropping a secret-shaped finding, so Config.Unfiltered has one place to
// switch off rather than a bool threaded through each call site.
//
// suppress answers "drop it?" exactly as the old boolean gates did. reason
// is non-empty only in the one remaining combination: the gate WOULD have
// dropped it but Unfiltered kept it alive — the caller stamps it onto
// Finding.UnfilteredOnly/UnfilteredReason so the report can mark the
// finding as gate-suppressed instead of presenting it as a normal one.
func (c Config) nameGate(key string) (suppress bool, reason string) {
	r := NonSecretNameReason(key)
	if r == "" {
		return false, ""
	}
	if c.Unfiltered {
		return false, r
	}
	return true, ""
}

func (c Config) valueGate(value string) (suppress bool, reason string) {
	r := NonSecretValueReason(value)
	if r == "" {
		return false, ""
	}
	if c.Unfiltered {
		return false, r
	}
	return true, ""
}
