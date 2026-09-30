// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// gh's account commands under a wrap. The shim injects GH_TOKEN into every
// gh call, and gh treats an environment token as outranking its own
// keyring: `gh auth switch`, `login` and `refresh` refuse outright ("The
// value of the GH_TOKEN environment variable is being used for
// authentication"), and even a switch run past the shim would change
// nothing, because the next wrapped call injects the same vault token
// again. The wrap, not gh's keyring, decides the account — so these
// commands are answered by jit, against the wrap: one vault secret per
// account (GhAccountVaultPath), and the wrap-gh profile pointing GH_TOKEN
// at whichever one is in use. See internal/cli/ghauth.go for the flow.

// GhHost is the host a wrap's accounts belong to. gh reads GH_TOKEN for
// github.com, and also for GHE.com tenancy hosts (*.ghe.com) and
// github.localhost (go-gh pkg/auth); a GitHub Enterprise Server host reads
// GH_ENTERPRISE_TOKEN instead, so its account commands are untouched by
// the wrap and take the normal path.
const GhHost = "github.com"

// ghAccountPrefix is where per-account tokens live in the vault.
const ghAccountPrefix = "wrap-gh/accounts/"

// ghLoginPattern is GitHub's username shape: alphanumerics and single
// hyphens, plus the underscore Enterprise Managed Users carry before their
// enterprise shortcode (alice_acme), which also lengthens the name past
// the usual 39. A name outside it never reaches a vault path or an argv.
var ghLoginPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_]|-[A-Za-z0-9]){0,99}$`)

// ValidGhLogin reports whether name can be a GitHub username.
func ValidGhLogin(name string) bool { return ghLoginPattern.MatchString(name) }

// GhAccountVaultPath is the vault path holding one account's token.
func GhAccountVaultPath(login string) string { return ghAccountPrefix + login }

// GhAccountFromVaultPath is GhAccountVaultPath's inverse: the account a
// vault path holds, or "" for any other path (the single-token
// wrap-gh/GH_TOKEN that `jit wrap gh` writes names no account).
func GhAccountFromVaultPath(path string) string {
	login, ok := strings.CutPrefix(path, ghAccountPrefix)
	if !ok || !ValidGhLogin(login) {
		return ""
	}
	return login
}

// GhAccountsInVault picks the account names out of a vault listing.
func GhAccountsInVault(paths []string) []string {
	var out []string
	for _, p := range paths {
		if login := GhAccountFromVaultPath(p); login != "" {
			out = append(out, login)
		}
	}
	sort.Strings(out)
	return out
}

// GhAuthCommand is one parsed `gh auth <sub>` invocation the shim answers
// itself. Help asks gh for its own text and is never matched.
type GhAuthCommand struct {
	Sub  string // switch, login, logout or refresh
	User string // --user / -u, "" when not given
	Host string // --hostname / -h, "" when not given
}

// OtherHost reports whether the command names a host GH_TOKEN doesn't
// cover (an Enterprise Server): the wrap is no obstacle there.
func (c GhAuthCommand) OtherHost() bool {
	return c.Host != "" && c.Host != GhHost && !c.TokenHost()
}

// TokenHost reports whether the command names a host other than github.com
// that GH_TOKEN still covers: gh refuses the account command while the
// token is set, but the wrap's accounts are github.com's, so it runs with
// no token and the wrap stays as it is.
func (c GhAuthCommand) TokenHost() bool {
	h := strings.ToLower(c.Host)
	return h == "github.localhost" || strings.HasSuffix(h, ".ghe.com")
}

// ParseGhAuth recognizes the gh account commands a wrap has to answer:
// `gh auth switch|login|logout|refresh`. Anything else, and any of these
// asking for --help, is not matched and takes the normal wrapped path.
// gh's -h means --hostname on these commands, not help.
func ParseGhAuth(args []string) (GhAuthCommand, bool) {
	if len(args) < 2 || args[0] != "auth" {
		return GhAuthCommand{}, false
	}
	cmd := GhAuthCommand{Sub: args[1]}
	switch cmd.Sub {
	case "switch", "login", "logout", "refresh":
	default:
		return GhAuthCommand{}, false
	}
	rest := args[2:]
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if arg == "--help" {
			return GhAuthCommand{}, false
		}
		name, value, hasValue := strings.Cut(arg, "=")
		var dst *string
		switch name {
		case "--user", "-u":
			dst = &cmd.User
		case "--hostname", "-h":
			dst = &cmd.Host
		default:
			continue
		}
		if !hasValue {
			if i+1 >= len(rest) {
				continue // gh reports the missing value itself
			}
			i++
			value = rest[i]
		}
		*dst = value
	}
	return cmd, true
}

// GhConfigDir is where gh keeps hosts.yml, by gh's own precedence:
// GH_CONFIG_DIR, then $XDG_CONFIG_HOME/gh, then ~/.config/gh.
func GhConfigDir(home string) string {
	if dir := os.Getenv("GH_CONFIG_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "gh")
	}
	return filepath.Join(home, ".config", "gh")
}

// GhKeyringAccounts reads which github.com accounts gh itself is signed in
// to, and which one it treats as active, from hosts.yml. Names only: the
// tokens sit in the macOS keyring (or, on old setups, in this same file,
// which is never returned). A missing file means no accounts.
func GhKeyringAccounts(home string) (logins []string, active string, err error) {
	path := filepath.Join(GhConfigDir(home), "hosts.yml")
	data, err := os.ReadFile(path) // #nosec G304 -- gh's own config file under the user's home or their GH_CONFIG_DIR
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("reading %s: %w", path, err)
	}
	var hosts map[string]struct {
		User  string               `yaml:"user"`
		Users map[string]yaml.Node `yaml:"users"`
	}
	if err := yaml.Unmarshal(data, &hosts); err != nil {
		return nil, "", fmt.Errorf("parsing %s: %w", path, err)
	}
	host := hosts[GhHost]
	for login := range host.Users {
		if ValidGhLogin(login) {
			logins = append(logins, login)
		}
	}
	// gh before multi-account support (2.40) wrote only `user:`.
	if len(logins) == 0 && ValidGhLogin(host.User) {
		logins = append(logins, host.User)
	}
	sort.Strings(logins)
	if ValidGhLogin(host.User) {
		active = host.User
	}
	return logins, active, nil
}

// PickGhSwitchTarget decides which account `gh auth switch` with no --user
// means, the way gh does: with exactly one other account, that one;
// otherwise the user has to say. known is every account jit could switch
// to, current the one the wrap uses ("" when it can't tell).
func PickGhSwitchTarget(known []string, current string) (string, error) {
	var others []string
	for _, login := range known {
		if login != current {
			others = append(others, login)
		}
	}
	switch {
	case len(others) == 1 && current != "":
		return others[0], nil
	case len(known) == 0:
		return "", fmt.Errorf("no GitHub accounts to switch to, `gh auth login` signs one in")
	default:
		return "", fmt.Errorf("say which account: `gh auth switch --user <name>` (%s)", strings.Join(known, ", "))
	}
}

// RealTool finds the real binary a shim named tool stands in for: the
// first one on PATH past the shim directory.
func RealTool(home, tool string) (string, error) {
	realTool, err := lookPathSkipping(os.Getenv("PATH"), tool, ShimDir(home))
	if err != nil {
		return "", fmt.Errorf("real %q not found in PATH beyond the shim directory, `jit wrap undo %s` removes the shim", tool, tool)
	}
	return realTool, nil
}
