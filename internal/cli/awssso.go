// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// The credential_process half of a sealed AWS sign-in, SSO or `aws login`
// (design/aws-sso-sealed.md). `jit migrate` rewrites each such profile to
// run `jit aws-sso --profile <name>`; this unseals the logins into a
// private HOME for one run of AWS's own `aws configure export-credentials`,
// which does the refresh, the rotation and GetRoleCredentials, and seals
// them again if that run changed them. jit speaks no SSO or sign-in itself.

var (
	awsSSOProfile      string
	awsSSOLoginProfile string
	awsSSOLoginRemote  bool
)

// awsSSOTimeout bounds the inner AWS CLI: a credential_process caller
// (terraform, an SDK) waits on it with no timeout of its own, and a hung
// network call must not hang the user's tool forever. A sign-in waits on
// a person in a browser instead, so it gets longer.
const (
	awsSSOTimeout      = 2 * time.Minute
	awsSSOLoginTimeout = 15 * time.Minute
)

var awsSSOCmd = &cobra.Command{
	Use:     "aws-sso --profile <name>",
	GroupID: groupPlumbing,
	// Hidden from tab-completion only, like aws-credential-process: the root
	// help and generated docs still list it.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Print AWS credential_process JSON for a sealed AWS profile",
	Long: "Not typically run by hand: jit migrate rewrites each AWS SSO and `aws login`\n" +
		"profile in ~/.aws/config to `credential_process = jit aws-sso --profile <name>`.\n" +
		"The login lives in the vault; this unpacks it into a private folder for one\n" +
		"run of `aws configure export-credentials` (AWS's own CLI does the refresh),\n" +
		"seals it again if the run refreshed it, and prints the credentials. A login\n" +
		"`aws sso login` just wrote to ~/.aws/sso/cache is moved into the vault first.\n" +
		"Needs the AWS CLI v2 on PATH.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if awsSSOProfile == "" {
			return fmt.Errorf("jit aws-sso: --profile is required")
		}
		// The service's cache first (D7): role credentials it holds in memory
		// from an earlier fetch, served after the same consent an unseal
		// would ask, without running the AWS CLI at all.
		if out, ok, err := awsSSOCachedCredentials(awsSSOProfile); err != nil {
			return err
		} else if ok {
			_, err = cmd.OutOrStdout().Write(out)
			return err
		}
		out, err := runAWSSSO(cmd.ErrOrStderr(), awsSSOInvocation{
			profile: awsSSOProfile,
			args:    []string{"configure", "export-credentials", "--profile", awsSSOProfile, "--format", "process"},
		})
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(out)
		return err
	},
}

var awsSSOLoginCmd = &cobra.Command{
	Use:   "login --profile <name>",
	Short: "Sign a sealed AWS profile in again, straight into the vault",
	Long: "Runs AWS's own sign-in for a profile jit sealed, against the sealed\n" +
		"login rather than ~/.aws: `aws login` for a console-credentials profile,\n" +
		"`aws sso login` for an SSO one. The browser flow is AWS's; the new login\n" +
		"goes into the vault without touching disk in plaintext.\n\n" +
		"An `aws login` profile needs this: `aws login` refuses a profile that\n" +
		"fetches through jit. An SSO profile can also use plain `aws sso login`,\n" +
		"which jit seals on the next use.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if awsSSOLoginProfile == "" {
			return fmt.Errorf("jit aws-sso login: --profile is required")
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit aws-sso login: %w", err)
		}
		loginArgs, err := migrate.AWSSealedLoginArgs(root, awsSSOLoginProfile, awsSSOLoginRemote)
		if err != nil {
			return fmt.Errorf("jit aws-sso login: %w", err)
		}
		if _, err := runAWSSSO(cmd.ErrOrStderr(), awsSSOInvocation{
			profile: awsSSOLoginProfile,
			args:    loginArgs,
			stdin:   cmd.InOrStdin(),
			stdout:  cmd.OutOrStdout(),
		}); err != nil {
			return err
		}
		// A new login may be another identity: nothing cached from the old
		// one may answer for it.
		clearAWSSSOCache()
		fmt.Fprintf(cmd.OutOrStdout(), "Signed in; the login for %q is sealed in the vault.\n", awsSSOLoginProfile)
		return nil
	},
}

var awsSSOLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Sign out of every sealed AWS SSO and `aws login` session",
	Long: "Runs `aws sso logout` on the sealed login, the way it would run on\n" +
		"~/.aws/sso/cache: Identity Center ends the session server-side and the\n" +
		"token is deleted. Sealed `aws login` sessions are deleted the way\n" +
		"`aws logout --all` deletes them. Plain `aws sso logout` and `aws logout`\n" +
		"cannot do this once the login is sealed, since the cache they read is\n" +
		"empty.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := runAWSSSO(cmd.ErrOrStderr(), awsSSOInvocation{signOut: true}); err != nil {
			return err
		}
		clearAWSSSOCache()
		fmt.Fprintln(cmd.OutOrStdout(), "Signed out of AWS; the vault holds no AWS sign-in now.")
		return nil
	},
}

func init() {
	awsSSOCmd.Flags().StringVar(&awsSSOProfile, "profile", "", "the AWS profile to fetch credentials for (supplied by ~/.aws/config)")
	awsSSOLoginCmd.Flags().StringVar(&awsSSOLoginProfile, "profile", "", "the sealed AWS profile to sign in")
	awsSSOLoginCmd.Flags().BoolVar(&awsSSOLoginRemote, "remote", false, "sign in with a browser on another device (aws login --remote, aws sso login --use-device-code)")
	awsSSOCmd.AddCommand(awsSSOLoginCmd, awsSSOLogoutCmd)
	rootCmd.AddCommand(awsSSOCmd)
}

// awsSSOInvocation is one locked run of the AWS CLI on the unsealed login.
type awsSSOInvocation struct {
	profile string   // names the profile in errors ("" for a sign-out)
	args    []string // the AWS CLI's arguments
	// signOut runs `aws sso logout`, and `aws logout --all` when the login
	// holds an `aws login` session (an AWS CLI too old for `aws login`
	// has no `aws logout` either, and could not have made one).
	signOut bool
	// stdin and stdout, when set, are the user's terminal: a sign-in shows
	// a URL and may read a code. Then nothing is captured and no
	// credentials are returned.
	stdin  io.Reader
	stdout io.Writer
}

// awsSSORunBase is where run dirs live: jit's root, never $TMPDIR (D6).
func awsSSORunBase(root string) string { return filepath.Join(root, "aws-sso-run") }

// awsSSOBinary finds the real AWS CLI, skipping jit's shim dir.
var awsSSOBinary = func(home string) string {
	return wrap.RealBinary(home, os.Getenv("PATH"), "aws")
}

// runAWSSSO runs the AWS CLI on the unsealed login and returns its stdout.
func runAWSSSO(stderr io.Writer, inv awsSSOInvocation) ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	awsBin := awsSSOBinary(home)
	if awsBin == "" {
		return nil, fmt.Errorf("jit aws-sso: the AWS CLI (aws) is not on PATH; jit runs it to refresh the SSO login")
	}
	v, err := openVault()
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	return awsSSOWithLogin(stderr, v, home, root, awsBin, inv)
}

// awsSSOWithLogin is runAWSSSO's core, with the vault and the AWS CLI
// supplied, so a test can drive it with a stand-in CLI.
func awsSSOWithLogin(stderr io.Writer, v *vault.Vault, home, root, awsBin string, inv awsSSOInvocation) ([]byte, error) {
	// One run at a time (D4): the refresh rotates the token, and two runs
	// refreshing together would both present the same one.
	unlock, err := lockAWSSSO(root)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	defer unlock()

	if captured, err := migrate.CaptureAWSSSOLogin(v, home); err != nil {
		return nil, fmt.Errorf("jit aws-sso: sealing the login aws sso login just wrote: %w", err)
	} else if captured {
		// A new login may be another identity: nothing cached from the old
		// one may answer for it.
		clearAWSSSOCache()
	}
	var blob []byte
	sealed, err := migrate.AWSSSOSealed(v)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	if sealed {
		// The consent prompt happens here: one unwrap of an aws-class value.
		if blob, err = v.Get(migrate.AWSSSOStorePath); err != nil {
			return nil, fmt.Errorf("jit aws-sso: the AWS SSO login stays sealed: %w", err)
		}
	}

	base := awsSSORunBase(root)
	_, _ = sealstore.Sweep(base, runOwnerAlive)
	start, _ := lineage.ProcessStartTime(int32(os.Getpid())) // #nosec G115 -- a pid always fits in int32 on darwin
	runDir, err := sealstore.NewRunDir(base, os.Getpid(), start)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	defer func() { _ = os.RemoveAll(runDir) }()
	awsDir := filepath.Join(runDir, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	if len(blob) > 0 {
		if err := migrate.AWSSSOLayout.Unpack(blob, awsDir); err != nil {
			return nil, fmt.Errorf("jit aws-sso: %w", err)
		}
	}
	baseline, err := migrate.AWSSSOLayout.Pack(awsDir)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}

	runs := [][]string{inv.args}
	if inv.signOut {
		runs = [][]string{{"sso", "logout"}}
		if entries, _ := os.ReadDir(filepath.Join(awsDir, "login", "cache")); len(entries) > 0 {
			runs = append(runs, []string{"logout", "--all"})
		}
	}
	timeout := awsSSOTimeout
	if inv.stdout != nil {
		timeout = awsSSOLoginTimeout
		// Ctrl-C is for the sign-in: it ends the AWS CLI (same process
		// group), and jit lives on to seal what it left and clean up.
		ints := make(chan os.Signal, 1)
		signal.Notify(ints, os.Interrupt)
		defer signal.Stop(ints)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var stdout bytes.Buffer
	var runErr error
	var errOut bytes.Buffer
	for _, args := range runs {
		c := exec.CommandContext(ctx, awsBin, args...) // #nosec G204 -- awsBin is the AWS CLI found on PATH; args are jit's own fixed commands
		c.Env = awsSSOEnv(os.Environ(), runDir, migrate.AWSSSOSealedConfigPath(root))
		c.Stdout, c.Stderr = &stdout, &errOut
		if inv.stdout != nil {
			c.Stdin, c.Stdout, c.Stderr = inv.stdin, inv.stdout, io.MultiWriter(stderr, &errOut)
		}
		if runErr = c.Run(); runErr != nil {
			break
		}
	}

	// Reseal whatever the run left, success or not: a refresh that rotated
	// the token before a later step failed has still spent the old one.
	if after, err := migrate.AWSSSOLayout.Pack(awsDir); err == nil && !bytes.Equal(after, baseline) {
		if err := migrate.StoreAWSSSOCache(v, home, after); err != nil {
			fmt.Fprintf(stderr, "jit aws-sso: could not seal the refreshed login: %v\n", err)
		}
	}
	if runErr != nil {
		return nil, awsSSOError(inv.profile, errOut.String(), runErr)
	}
	if args := inv.args; inv.profile != "" && len(args) > 1 && args[0] == "configure" && args[1] == "export-credentials" {
		cacheAWSSSOCredentials(inv.profile, stdout.Bytes())
	}
	return stdout.Bytes(), nil
}

// awsCredCache is the service's AWS cache as `jit aws-sso` uses it
// (agent.Client), so a test can stand in for the service.
type awsCredCache interface {
	AWSCacheGet(profile string) ([]byte, bool, error)
	AWSCachePut(profile string, data []byte, expires time.Time) error
	AWSCacheClear() error
}

// awsSSOCache returns the running service's cache, or nil when no service
// answers. No retry and no kickstart: a missing cache is only a slower
// fetch, never a reason to start anything.
var awsSSOCache = func() awsCredCache {
	root, err := vaultRootDir()
	if err != nil {
		return nil
	}
	c := agent.NewClient(agent.SocketPath(root))
	if !c.Reachable() {
		return nil
	}
	return c
}

// awsSSOCachedCredentials asks the service for profile's cached
// credentials. Skipped while `aws sso login` has a login waiting in the
// real cache: that login must be sealed by a real fetch, not left in
// plaintext for as long as the cache could answer. A consent refusal is
// returned (the user said no; a fallback unseal would only ask again);
// anything else, an older service included, is a miss.
func awsSSOCachedCredentials(profile string) ([]byte, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false, nil
	}
	if entries, _ := os.ReadDir(migrate.AWSSSOCacheDir(home)); len(entries) > 0 {
		return nil, false, nil
	}
	c := awsSSOCache()
	if c == nil {
		return nil, false, nil
	}
	data, ok, err := c.AWSCacheGet(profile)
	if err != nil {
		if strings.Contains(err.Error(), "consent") {
			return nil, false, fmt.Errorf("jit aws-sso: %w", err)
		}
		return nil, false, nil
	}
	return data, ok, nil
}

// cacheAWSSSOCredentials offers credentials just fetched to the service,
// best effort: it accepts them only from the process that just read the
// sealed login, which this one is.
func cacheAWSSSOCredentials(profile string, out []byte) {
	var doc struct {
		Expiration string `json:"Expiration"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return
	}
	exp, err := time.Parse(time.RFC3339, doc.Expiration)
	if err != nil {
		return
	}
	if c := awsSSOCache(); c != nil {
		_ = c.AWSCachePut(profile, out, exp)
	}
}

// clearAWSSSOCache empties the service's AWS cache, best effort.
func clearAWSSSOCache() {
	if c := awsSSOCache(); c != nil {
		_ = c.AWSCacheClear()
	}
}

// awsSSOEnv is the inner CLI's environment: the caller's, minus anything
// that would point it elsewhere (AWS_LOGIN_CACHE_DIRECTORY would move the
// `aws login` cache out of the run dir), with HOME on the run dir (the
// CLI's caches resolve under it), the sealed config, and no shared
// credentials file. _AWS_CLI_PROFILE_CHAIN is export-credentials' loop
// guard: an outer `export-credentials --profile dev` sets it, and the inner
// run, resolving dev against the sealed config where dev IS the SSO
// profile, would refuse it as a cycle it is not (spike Result 2).
func awsSSOEnv(environ []string, runDir, sealedConfig string) []string {
	drop := []string{
		"HOME=", "AWS_CONFIG_FILE=", "AWS_SHARED_CREDENTIALS_FILE=", "_AWS_CLI_PROFILE_CHAIN=", "AWS_LOGIN_CACHE_DIRECTORY=",
		"AWS_PROFILE=", "AWS_DEFAULT_PROFILE=", "AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=",
	}
	out := make([]string, 0, len(environ)+3)
next:
	for _, kv := range environ {
		for _, d := range drop {
			if strings.HasPrefix(kv, d) {
				continue next
			}
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+runDir, "AWS_CONFIG_FILE="+sealedConfig, "AWS_SHARED_CREDENTIALS_FILE=/dev/null")
}

// awsSSOError turns the inner CLI's failure into what the caller should
// do. The AWS CLI shows a credential_process's stderr in its own error, so
// this sentence is what the user reads under `aws s3 ls`.
func awsSSOError(profile, stderr string, runErr error) error {
	msg := strings.TrimSpace(stderr)
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "error loading sso token") || strings.Contains(lower, "token for") && strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "token has expired") || strings.Contains(lower, "refresh failed") ||
		strings.Contains(lower, "error loading login session token") || strings.Contains(lower, "reauthenticate") {
		login := "jit aws-sso login"
		if profile != "" {
			login += " --profile " + profile
		}
		return fmt.Errorf("jit aws-sso: no current AWS sign-in for this profile; run `%s`", login)
	}
	if errors.Is(runErr, context.DeadlineExceeded) {
		return fmt.Errorf("jit aws-sso: the AWS CLI did not answer within %s", awsSSOTimeout)
	}
	if msg == "" {
		return fmt.Errorf("jit aws-sso: aws %v", runErr)
	}
	return fmt.Errorf("jit aws-sso: %s", msg)
}

// lockAWSSSO takes the exclusive run lock, blocking until it is free.
func lockAWSSSO(root string) (func(), error) {
	dir := filepath.Join(root, "aws-sso")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- jit's own lock file under its root
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits in int
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- as above
		_ = f.Close()
	}, nil
}
