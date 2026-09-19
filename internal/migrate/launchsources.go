// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

// The artifacts `jit migrate` writes that launch a profile BY NAME, read back
// for the launcher map (internal/launchers, design/doctor-repair.md F1). They
// live here, beside the writers, for the reason DiscoverRecordedJitPaths
// does: the reader and the writer must agree about what an artifact looks
// like. DiscoverRecordedJitPaths reads the same files for the jit PATH they
// record; these read them for the PROFILE they name.
//
// Every reader is read-only and fixed-path. A missing file is nothing to
// report, (nil, nil); an unreadable or unparseable one is an error, so a
// deleting caller never reads "can't tell" as "nothing launches it".
// Environment overrides are deliberately not honoured: $AWS_CONFIG_FILE and
// $KUBECONFIG are read by no jit writer either, so a file they name was never
// rewritten by jit and names no jit profile.

// A ProfileLaunch is one line of one artifact that launches a jit profile by
// name.
type ProfileLaunch struct {
	File    string // the artifact
	Profile string // the profile name it passes to jit
	// Detail says where in the file, the way the user thinks of it:
	// "[profile dev]" in ~/.aws/config, "user docker-desktop" in a
	// kubeconfig, "line 12" in a shell rc file.
	Detail string
	Line   int // 1-based line number, 0 when the format has none (YAML)
}

// AWSConfigProfileLaunches reads every credential_process line in
// ~/.aws/config that runs `jit aws-credential-process --profile <name>`.
// The AWS profile section is the detail; the jit profile is the launch.
func AWSConfigProfileLaunches(home string) ([]ProfileLaunch, error) {
	path := AWSConfigPath(home)
	lines, err := readLaunchSource(path)
	if err != nil || lines == nil {
		return nil, err
	}
	var out []ProfileLaunch
	section := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "credential_process") {
			continue
		}
		name := jitSubcommandProfile(splitCommandLine(strings.TrimSpace(value)), "aws-credential-process")
		if name == "" {
			continue
		}
		detail := ""
		if section != "" {
			detail = "[" + section + "]"
		}
		out = append(out, ProfileLaunch{File: path, Profile: name, Detail: detail, Line: i + 1})
	}
	return out, nil
}

// KubeconfigProfileLaunches reads every user in ~/.kube/config whose exec
// plugin runs `jit k8s-exec-credential --profile <name>`.
func KubeconfigProfileLaunches(home string) ([]ProfileLaunch, error) {
	path := KubeconfigPath(home)
	doc, err := loadKubeconfig(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	users, err := kubeconfigUsers(doc)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var out []ProfileLaunch
	for _, u := range users {
		userName, _ := u["name"].(string)
		userMap, _ := u["user"].(map[string]interface{})
		exec, _ := userMap["exec"].(map[string]interface{})
		rawArgs, _ := exec["args"].([]interface{})
		args := make([]string, 0, len(rawArgs))
		for _, a := range rawArgs {
			s, _ := a.(string)
			args = append(args, s)
		}
		name := jitSubcommandProfile(args, "k8s-exec-credential")
		if name == "" {
			continue
		}
		out = append(out, ProfileLaunch{File: path, Profile: name, Detail: "user " + userName})
	}
	return out, nil
}

// shellExportProfile matches the `jit export --profile <name>` call
// ApplyShellConfig writes (`eval "$(jit export --profile <name>)"`), with
// the jit binary named any way and --profile=<name> accepted too. The name
// class is profile.Path's own allowlist.
var shellExportProfile = regexp.MustCompile(`(?:^|[\s"'(;&|])(?:\S*/)?jit\s+export\s+--profile(?:\s+|=)["']?([A-Za-z0-9_.-]+)`)

// ShellRCProfileLaunches reads the shell rc files migrate converts
// (ShellConfigPaths) for `jit export --profile <name>` lines. The rc file
// itself is the source, not migrate's backup index: the index records what
// was once written, the file says what runs in the next shell. A commented
// out line runs nothing and is skipped. Every readable file is reported
// even when another fails; the failures come back joined.
func ShellRCProfileLaunches(home string) ([]ProfileLaunch, error) {
	var out []ProfileLaunch
	var errs []error
	for _, path := range ShellConfigPaths(home) {
		lines, err := readLaunchSource(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range shellExportProfile.FindAllStringSubmatch(line, -1) {
				out = append(out, ProfileLaunch{File: path, Profile: m[1], Detail: fmt.Sprintf("line %d", i+1), Line: i + 1})
			}
		}
	}
	return out, errors.Join(errs...)
}

// A CredentialHelper is one helper script jit migrate writes for a tool that
// finds its credential helper by executable name. The helper names no
// profile: it derives one per request from the registry or host the tool
// asks about, always under ProfilePrefix in the global store.
type CredentialHelper struct {
	Label         string // the way the user thinks of it, as in RecordedJitPath
	Path          string
	Category      string // the --only token that writes it
	ProfilePrefix string // every profile it can serve starts with this
}

// CredentialHelpers lists the four helper scripts, whether or not each
// exists, from the same path functions DiscoverRecordedJitPaths reads.
func CredentialHelpers(home string) []CredentialHelper {
	return []CredentialHelper{
		{Label: "the docker credential helper", Path: DockerHelperPath(home), Category: "docker", ProfilePrefix: dockerProfilePrefix},
		{Label: "the git credential helper", Path: GitHelperPath(home), Category: "git", ProfilePrefix: gitProfilePrefix},
		{Label: "the terraform credentials helper", Path: TerraformHelperPath(home), Category: "terraform", ProfilePrefix: terraformProfilePrefix},
		{Label: "the cargo credential provider", Path: CargoHelperPath(home), Category: "cargo", ProfilePrefix: cargoProfilePrefix},
	}
}

// SkipDiscoveryDir is the directory rule every migrate discovery walk
// applies (audit's noise list, .jit, the Go module cache), exported for a
// walk that lives outside this package and must prune exactly the same set.
func SkipDiscoveryDir(root, path, name string) bool {
	return skipDiscoveryDir(root, path, name)
}

// readLaunchSource reads a fixed artifact as lines: nil, nil for a file
// that does not exist.
func readLaunchSource(path string) ([]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed, jit-owned artifact locations under home
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return strings.Split(string(data), "\n"), nil
}

// jitSubcommandProfile returns the --profile value of an argv that runs the
// given jit subcommand, or "" when it doesn't. The subcommand token is the
// anchor, not the binary's path: a launcher whose jit path went stale still
// names its profile, and another tool's --profile flag is not jit's.
func jitSubcommandProfile(argv []string, subcommand string) string {
	sub := -1
	for i, a := range argv {
		if a == subcommand {
			sub = i
			break
		}
	}
	if sub < 0 {
		return ""
	}
	for i := sub + 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		if a == "--profile" && i+1 < len(argv) {
			return argv[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--profile="); ok {
			return v
		}
	}
	return ""
}

// splitCommandLine tokenizes a credential_process value the way botocore
// does, closely enough for the lines quoteIfNeeded writes: whitespace
// separates, single quotes are literal, double quotes group and honour a
// backslash escape.
func splitCommandLine(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1 // unterminated: the rest is the word
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == ' ' || c == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}
