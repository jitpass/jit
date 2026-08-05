// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// mcpConfigFileNames are exact filenames recognized as MCP/AI-tool configs
// during the broad home-directory walk. Claude Desktop's config lives under
// ~/Library, which walkHomeDir deliberately skips (noiseDirs) — it's
// checked separately via a fixed path below.
var mcpConfigFileNames = map[string]bool{
	"mcp.json":                   true,
	".mcp.json":                  true,
	"claude_desktop_config.json": true,
}

// mcpConfigFile covers both "mcpServers" (Claude Desktop, Cursor) and
// "servers" (VS Code's MCP schema) top-level keys, since this is a
// fast-moving ecosystem and tools haven't converged on one key name.
type mcpConfigFile struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	Servers    map[string]mcpServerEntry `json:"servers"`
	// Projects is Claude Code's own store (~/.claude.json), which keys a
	// second set of server definitions by project directory alongside the
	// top-level block. Without it, a project-scoped server in that file is
	// invisible even once the filename is recognized.
	Projects map[string]struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	} `json:"projects"`
}

// mcpServerEntry decodes every field of a server entry that can carry a
// credential. It was `Env` alone for a long time, which made this scanner
// structurally blind to five of the six shapes a real config uses: a
// credential passed by `--env-file <path>`, one baked into `args`, one in a
// remote server's `headers`, one in its `url`, and (via args) `docker run -e`.
// Measured on a config holding all six, jit reported one.
//
// Command is decoded but not swept: an executable path is not a credential,
// and the tokens that matter live in the arguments after it.
type mcpServerEntry struct {
	Env     map[string]string `json:"env"`
	Args    []string          `json:"args"`
	Command string            `json:"command"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	// Cwd is what a relative --env-file resolves against, when the entry
	// sets it. Otherwise the config file's own directory is used.
	Cwd string `json:"cwd"`
}

// mcpCredentialHeaderNames are header names whose presence on an MCP server
// entry means the value is an access credential. Name-gated rather than
// swept by value, because a bearer token issued by a private provider
// matches no vendor pattern — the same reasoning that makes every key in an
// `env` block a finding regardless of its shape. Ordinary transport headers
// (Content-Type, Accept, User-Agent) are deliberately absent.
var mcpCredentialHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
	"apikey":              true,
	"x-auth-token":        true,
	"auth-token":          true,
	"x-access-token":      true,
	"token":               true,
	"cookie":              true,
}

// ScanMCPConfigs implements RFC.md §4 category 4: embedded secrets in
// mcp.json-family files. Findings are per-key inside a server's env block —
// RFC's risk table says "any MCP-embedded secret" (singular), implying each
// embedded credential is its own finding, unlike .env's file-level
// granularity. Every key inside an env block is still flagged (not gated by
// the secret-keyword heuristic shell configs use — an MCP env block exists
// specifically to inject credentials into that server process, so anything
// there is credential-shaped by construction), but a value that looks like
// a bare URL (LooksLikeBareURL) gets lowered severity/confidence rather
// than being treated identically to an opaque API key — real-world review
// (2026-07-06) found a plain tool-endpoint URL (CAIDO_URL) getting flagged
// exactly like a real credential, which is noise, not signal.
func ScanMCPConfigs(cfg Config) ([]Finding, error) {
	fixed, err := scanClaudeDesktopMCPConfig(cfg)
	if err != nil {
		return nil, err
	}
	walked, err := walkForCategory(cfg, classifyMCPFile)
	// Composed exactly as Scan composes the two halves — see
	// ScanCredentialFiles. No walk can currently reach the Claude Desktop
	// config (~/Library is pruned), so nothing is dropped in practice; using
	// the same expression everywhere is what stops that from being a fact
	// someone has to re-verify per category.
	return append(fixed, dropAlreadyReported(fixed, walked)...), err
}

// scanClaudeDesktopMCPConfig is the known-location half of the MCP category:
// Claude Desktop's config lives at one fixed path under ~/Library, which the
// discovery walk deliberately never reaches (noiseDirs prunes Library), so it
// has to be probed directly.
func scanClaudeDesktopMCPConfig(cfg Config) ([]Finding, error) {
	var findings []Finding
	for _, path := range fixedMCPConfigPaths(cfg.HomeDir) {
		if _, err := os.Stat(path); err != nil {
			continue // absent (or unstattable) — nothing to scan, never an error
		}
		fs, err := scanMCPConfigFile(cfg, path)
		if err != nil {
			continue
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

// fixedMCPConfigPaths are MCP configs at known absolute locations, probed
// directly because the home walk cannot or would not reach them.
//
// Claude Desktop's lives under ~/Library, which walkHomeDir prunes outright.
// ~/.claude.json is Claude Code's own store: the walk DOES reach it, but the
// filename is not in mcpConfigFileNames and adding it there would be wrong —
// ".claude.json" is a whole application state file that merely contains an
// mcpServers block, not an MCP config by name. Dogfooding found a real one
// holding a server with an env block, unscanned.
func fixedMCPConfigPaths(home string) []string {
	return []string{
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".claude.json"),
	}
}

// classifyMCPFile is the name-gated per-file half of the MCP category, split
// out so the machine-wide walk (see categories) and `jit scan <path>`'s
// targeted walk recognize the same mcp.json / .mcp.json /
// claude_desktop_config.json names. Returns nil for a name that isn't a known
// MCP config file, and for one that is but can't be parsed (skip, never fail).
//
// No guard against re-reporting the Claude Desktop config scanned above is
// needed: walkHomeDir prunes ~/Library outright, so no home walk can reach
// that path. Leaving the guard out is also what keeps `jit scan
// ~/Library/Application\ Support/Claude` — a path the user named explicitly,
// where the known-location half never runs — reporting anything at all.
func classifyMCPFile(cfg Config, path, name string) []Finding {
	if !mcpConfigFileNames[name] {
		return nil
	}
	findings, err := scanMCPConfigFile(cfg, path)
	if err != nil {
		return nil
	}
	return findings
}

func scanMCPConfigFile(cfg Config, path string) ([]Finding, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mc mcpConfigFile
	// Bounded for the same reason inspectK8sSecretFile's decoder is: this runs
	// on any walked mcp.json, and json.Decoder will happily build whatever the
	// file describes.
	if err := json.NewDecoder(io.LimitReader(file, maxStructuredParseSize)).Decode(&mc); err != nil {
		return nil, nil // malformed JSON — not our job to validate it, just skip
	}

	servers := mc.MCPServers
	if len(servers) == 0 {
		servers = mc.Servers
	}
	// A project-scoped server is merged in under a qualified name, so two
	// projects defining "github" stay distinguishable in the report and get
	// distinct record IDs. Merged rather than scanned separately because
	// everything below is per-server and cares only about the entry.
	for _, project := range slices.Sorted(maps.Keys(mc.Projects)) {
		for _, name := range slices.Sorted(maps.Keys(mc.Projects[project].MCPServers)) {
			if servers == nil {
				servers = map[string]mcpServerEntry{}
			}
			servers[filepath.Base(project)+"/"+name] = mc.Projects[project].MCPServers[name]
		}
	}

	// Both loops iterate sorted keys rather than raw map order — see
	// scanAWSCredentials for why. This file is where it bit hardest: a single
	// mcp.json commonly holds several servers with several env keys each, so
	// its findings reshuffled on every run.
	var findings []Finding
	for _, serverName := range slices.Sorted(maps.Keys(servers)) {
		entry := servers[serverName]
		for _, envKey := range slices.Sorted(maps.Keys(entry.Env)) {
			envValue := entry.Env[envKey]
			if envValue == "" {
				continue
			}

			severity, confidence, evidence := SeverityHigh, ConfidenceHigh,
				fmt.Sprintf("embedded directly in MCP server %q's env block", serverName)
			if looksLikePlainSetting(envKey, envValue) {
				// The "everything in an env block is a credential" rule holds
				// for a .mcp.json a human wrote to hand a server its token.
				// It does not hold for an application-state file a TOOL
				// writes (~/.claude.json), where the same block carries
				// ordinary settings — CRAWL4AI_LANG="en" reported HIGH the
				// moment that file came into scope, which is noise of exactly
				// the kind the CAIDO_URL case below was fixed for.
				//
				// De-escalated, never suppressed, and deliberately powerless
				// against the cross-cutting signals: ValueFinding still
				// escalates to Critical on a production-indicator or public-IP
				// match, so a short value that names prod cannot hide here.
				severity, confidence = SeverityLow, ConfidenceLow
				evidence = fmt.Sprintf("a short plain setting in MCP server %q's env block, not credential-shaped", serverName)
			} else if LooksLikeBareURL(envValue) {
				// A plain URL with no embedded credentials is often just a
				// service endpoint (e.g. CAIDO_URL pointing at a local
				// proxy), not a secret — lower confidence rather than
				// suppress, since a URL CAN still embed a secret (a
				// webhook token in the path) that this heuristic misses.
				severity, confidence = SeverityLow, ConfidenceLow
				// Keep this terse: the reason renders on one line in the
				// report, and the full endpoint-vs-webhook-token nuance made
				// it the longest line on real machines by a wide margin.
				evidence = fmt.Sprintf("plain URL in MCP server %q's env block; URLs can embed tokens", serverName)
			}

			findings = append(findings, cfg.ValueFinding(ValueFindingParams{
				FindingType:  FindingTypeMCPEmbeddedSecret,
				FilePath:     path,
				KeyName:      fmt.Sprintf("%s/%s", serverName, envKey),
				RawValue:     envValue,
				BaseSeverity: severity,
				Confidence:   confidence,
				Evidence:     evidence,
			}))
		}

		findings = append(findings, scanMCPServerHeaders(cfg, path, serverName, entry)...)
		findings = append(findings, scanMCPServerURL(cfg, path, serverName, entry)...)
		findings = append(findings, scanMCPServerArgs(cfg, path, serverName, entry)...)
		findings = append(findings, scanMCPEnvFilePointers(cfg, path, serverName, entry)...)
	}
	return findings, nil
}

// withContextEvidence restores a scanner's own evidence over the generic
// sentence ValueFinding derives from a vendor pattern ("value matches X's
// known token format"). For these findings WHERE the credential sits is the
// whole point — on a command line `ps` exposes, in a URL that gets logged, in
// a header jit cannot reach — and that context is worth more to the reader
// than restating the pattern name, which the value preview already implies.
//
// A production-indicator or public-IP match still wins: those are the
// cross-cutting escalations RFC.md §4 says override everything, and silently
// replacing their evidence would hide why a finding went Critical.
func withContextEvidence(f Finding, evidence string) Finding {
	if f.ProductionIndicatorMatch || f.PublicIPMatch != nil {
		return f
	}
	f.Evidence = evidence
	return f
}

// looksLikePlainSetting reports whether an env-block entry is ordinary
// configuration rather than a credential: an unremarkable key paired with a
// short, low-entropy, word-or-number value ("en", "3000", "true", "debug").
//
// Both halves must agree. A secret-shaped NAME keeps its finding no matter
// how short the value is, because a six-character password is still a
// password, and a value carrying any vendor pattern or real entropy is
// caught by the checks it would otherwise slip past.
func looksLikePlainSetting(key, value string) bool {
	if LooksLikeSecretKey(key) || LooksLikeHighEntropySecret(key, value) {
		return false
	}
	if len(value) == 0 || len(value) > 12 {
		return false
	}
	if _, _, ok := MatchKnownTokenPattern(value); ok {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// scanMCPServerHeaders reports credentials on a remote (type http/sse) server
// entry. These are DETECT-ONLY by construction: the MCP host makes the HTTP
// request itself, so there is nothing for jit to inject into and no rewrite
// that would help. RemedyManual is set here rather than left to
// annotateRemedies, whose default would promise `jit migrate <file>` for
// something migrate cannot fix.
func scanMCPServerHeaders(cfg Config, path, serverName string, entry mcpServerEntry) []Finding {
	var findings []Finding
	for _, header := range slices.Sorted(maps.Keys(entry.Headers)) {
		value := entry.Headers[header]
		if value == "" {
			continue
		}
		named := mcpCredentialHeaderNames[strings.ToLower(strings.TrimSpace(header))]
		vendor, _, tokenOK := MatchKnownTokenPattern(value)
		if !named && !tokenOK {
			continue
		}
		evidence := fmt.Sprintf("sent as the %q header by MCP server %q; jit can't inject into a header the host itself sends", header, serverName)
		if tokenOK {
			evidence = fmt.Sprintf("%s's %q header carries a %s; jit can't inject into a header the host itself sends", serverName, header, vendor)
		}
		f := withContextEvidence(cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeMCPEmbeddedSecret,
			FilePath:     path,
			KeyName:      fmt.Sprintf("%s/header:%s", serverName, header),
			RawValue:     value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     evidence,
		}), evidence)
		f.Remedy = RemedyManual
		findings = append(findings, f)
	}
	return findings
}

// scanMCPServerURL reports a credential embedded in a remote server's URL
// ("https://mcp.example.com/sse?api_key=..."). The env-block scanner above
// already reasons that "URLs can embed tokens" when it sees one as a VALUE;
// it never looked at the field where that is most likely. Detect-only, for
// the same reason headers are.
func scanMCPServerURL(cfg Config, path, serverName string, entry mcpServerEntry) []Finding {
	if entry.URL == "" {
		return nil
	}
	vendor, _, ok := MatchKnownTokenPattern(entry.URL)
	if !ok {
		return nil
	}
	evidence := fmt.Sprintf("%s embedded in MCP server %q's endpoint URL; rotate it, a URL is logged and shared far more freely than a header", vendor, serverName)
	f := withContextEvidence(cfg.ValueFinding(ValueFindingParams{
		FindingType:  FindingTypeMCPEmbeddedSecret,
		FilePath:     path,
		KeyName:      fmt.Sprintf("%s/url", serverName),
		RawValue:     entry.URL,
		BaseSeverity: SeverityHigh,
		Confidence:   ConfidenceHigh,
		Evidence:     evidence,
	}), evidence)
	f.Remedy = RemedyManual
	return []Finding{f}
}

// scanMCPServerArgs reports a credential passed on a server's command line,
// including the `docker run -e KEY=value` form, which is just another
// argument. Value-swept rather than name-gated: an argument list is mostly
// ordinary flags and paths, so unlike an env block it cannot be treated as
// credential-bearing by construction.
//
// Detect-only. Rewriting a command line to pull one argument out is a
// transformation jit has no safe general rule for — the flag might be
// positional, repeated, or required — so this reports and leaves it.
func scanMCPServerArgs(cfg Config, path, serverName string, entry mcpServerEntry) []Finding {
	var findings []Finding
	for i, arg := range entry.Args {
		// "--api-key=sk-live-..." carries the credential in the same token as
		// the flag; test the half after the first "=" as well as the whole.
		// The value half is tried FIRST so the finding's masked preview shows
		// the credential ("sk-**********") rather than the flag that carries
		// it ("--ap**********"), which tells the reader nothing about what
		// leaked.
		candidates := []string{arg}
		if key, value, found := strings.Cut(arg, "="); found && value != "" && strings.HasPrefix(key, "-") {
			candidates = []string{value, arg}
		}
		for _, candidate := range candidates {
			vendor, _, ok := MatchKnownTokenPattern(candidate)
			if !ok {
				continue
			}
			// No leading article: vendor names start with both vowels and
			// consonants ("an OpenAI key", "a Slack token"), and picking one
			// at format time is a rule nobody maintains.
			evidence := fmt.Sprintf("%s on MCP server %q's command line, where `ps` shows it to every process running as you",
				vendor, serverName)
			f := withContextEvidence(cfg.ValueFinding(ValueFindingParams{
				FindingType:  FindingTypeMCPEmbeddedSecret,
				FilePath:     path,
				KeyName:      fmt.Sprintf("%s/args[%d]", serverName, i),
				RawValue:     candidate,
				BaseSeverity: SeverityHigh,
				Confidence:   ConfidenceHigh,
				Evidence:     evidence,
			}), evidence)
			f.Remedy = RemedyManual
			findings = append(findings, f)
			break // one finding per argument, whichever half matched first
		}
	}
	return findings
}

// mcpEnvFileArgs extracts every path a server's args deliver credentials
// from: "--env-file <path>" and "--env-file=<path>". The spelling is shared
// by uv, uvx, node and docker, so this is deliberately launcher-agnostic
// rather than keyed on the command — matching how ApplyMCPConfig already
// treats argv as opaque.
//
// Relative paths resolve against the entry's own "cwd" when it sets one, and
// otherwise against the config file's directory. Neither is guaranteed
// correct (the MCP host picks the real working directory), but a path that
// resolves to a real file is strong evidence the guess was right, and
// scanMCPEnvFilePointers reports nothing for a path it cannot stat.
func mcpEnvFileArgs(configPath string, entry mcpServerEntry) []string {
	return MCPEnvFileArgs(configPath, entry.Cwd, entry.Args)
}

// MCPEnvFileArgs is mcpEnvFileArgs over primitives, exported for
// internal/migrate.
//
// Shared rather than reimplemented on purpose: scan decides what to REPORT
// from this and migrate decides what to FIX from it, so any drift between
// the two spellings produces a finding whose offered fix silently skips it —
// which is the exact failure this whole feature exists to remove.
func MCPEnvFileArgs(configPath, cwd string, args []string) []string {
	base := cwd
	if base == "" {
		base = filepath.Dir(configPath)
	}
	var paths []string
	add := func(p string) {
		if p == "" {
			return
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		paths = append(paths, filepath.Clean(p))
	}
	for i, arg := range args {
		switch {
		case arg == "--env-file" && i+1 < len(args):
			add(args[i+1])
		case strings.HasPrefix(arg, "--env-file="):
			add(strings.TrimPrefix(arg, "--env-file="))
		}
	}
	return paths
}

// scanMCPEnvFilePointers reports that a server delivers its credentials from
// a file rather than an env block.
//
// This is the finding that closes the gap dogfooding found: a real config's
// okta and falcon servers each passed `--env-file` at a plaintext .env, and
// jit said nothing about either. The .env itself IS reported by ScanEnvFiles
// when it happens to be named .env-something, but nothing connected the two,
// so the report never said which server consumed the flagged file — and a
// target named anything else (secrets.env, config.env) was invisible
// outright, since envFileNamePattern gates that scanner on the filename.
//
// It deliberately does NOT re-report the target's contents. For a .env-named
// target that would count one exposure twice, once per category, and inflate
// the total. What this adds is the LINK, plus first-sight coverage for a
// target the name gate drops.
//
// Fixable, unlike the header/url/args findings above: `jit migrate <config>`
// absorbs the file into the server's profile, drops the --env-file flag, and
// leaves a pointer file behind. So this one takes annotateRemedies' default
// (RemedyMigrate) rather than setting RemedyManual, and the report's fix hint
// names a command that actually does something.
func scanMCPEnvFilePointers(cfg Config, path, serverName string, entry mcpServerEntry) []Finding {
	var findings []Finding
	for _, target := range mcpEnvFileArgs(path, entry) {
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() {
			// A dangling pointer exposes nothing, so it is not a scan
			// finding. `jit doctor` is where a config that cannot launch
			// belongs.
			continue
		}
		// An already-migrated target holds vault PATHS, not values. classifyEnvFile
		// guards its own scan with this; reaching buildEnvFileFinding directly
		// skipped it, and a neutralized file reported as "1 plaintext variable" —
		// noise, and it aimed the fix hint at a file with nothing left to move.
		if isJitPointerContent(target) {
			continue
		}

		// Classified by the env-file scanner itself, not by a second opinion
		// built here. FindFileTokens was the obvious probe and is the wrong
		// one: it skips every "... Private Key" pattern outright, since
		// ScanPrivateKeys owns key bodies, so a file whose only credential is
		// a PEM came back empty — which is precisely the file this feature
		// exists for. Delegating also means the two paths can never disagree
		// about whether the same file holds a secret.
		sub, found, berr := buildEnvFileFinding(cfg, target, isEnvTemplateFile(filepath.Base(target)))
		if berr != nil || !found {
			// The scanner that owns .env files says this one exposes
			// nothing. A server reading a file with no credential in it is
			// not a finding.
			continue
		}

		f := cfg.baseFinding()
		f.FindingType = FindingTypeMCPEmbeddedSecret
		f.FilePath = path
		key := serverName
		f.KeyName = &key
		f.Severity = sub.Severity
		f.Confidence = sub.Confidence
		f.ProductionIndicatorMatch = sub.ProductionIndicatorMatch
		f.PublicIPMatch = sub.PublicIPMatch
		f.Evidence = fmt.Sprintf("reads credentials from %s; that file %s",
			ShortenHome(cfg.HomeDir, target), sub.Evidence)
		f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
		findings = append(findings, f)
	}
	return findings
}
