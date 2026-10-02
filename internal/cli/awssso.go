// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// The credential_process half of a sealed AWS SSO login
// (design/aws-sso-sealed.md). `jit migrate` rewrites each SSO profile to run
// `jit aws-sso --profile <name>`; this unseals the token cache into a
// private HOME for one run of AWS's own `aws configure export-credentials`,
// which does the refresh, the rotation and GetRoleCredentials, and seals
// the cache again if that run changed it. jit speaks no SSO itself.

var awsSSOProfile string

// awsSSOTimeout bounds the inner AWS CLI: a credential_process caller
// (terraform, an SDK) waits on it with no timeout of its own, and a hung
// network call must not hang the user's tool forever.
const awsSSOTimeout = 2 * time.Minute

var awsSSOCmd = &cobra.Command{
	Use:     "aws-sso --profile <name>",
	GroupID: groupPlumbing,
	// Hidden from tab-completion only, like aws-credential-process: the root
	// help and generated docs still list it.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Print AWS credential_process JSON for a sealed SSO profile",
	Long: "Not typically run by hand: jit migrate rewrites each AWS SSO profile in\n" +
		"~/.aws/config to `credential_process = jit aws-sso --profile <name>`. The SSO\n" +
		"login lives in the vault; this unpacks it into a private folder for one run\n" +
		"of `aws configure export-credentials` (AWS's own CLI does the refresh), seals\n" +
		"it again if the run refreshed it, and prints the credentials. A login\n" +
		"`aws sso login` just wrote to ~/.aws/sso/cache is moved into the vault first.\n" +
		"Needs the AWS CLI v2 on PATH.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if awsSSOProfile == "" {
			return fmt.Errorf("jit aws-sso: --profile is required")
		}
		out, err := runAWSSSO(cmd.ErrOrStderr(), awsSSOProfile, []string{"configure", "export-credentials", "--profile", awsSSOProfile, "--format", "process"})
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(out)
		return err
	},
}

var awsSSOLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Sign out of every sealed AWS SSO session",
	Long: "Runs `aws sso logout` on the sealed login, the way it would run on\n" +
		"~/.aws/sso/cache: Identity Center ends the session server-side and the\n" +
		"token is deleted. Plain `aws sso logout` cannot do this once the login is\n" +
		"sealed, since the cache it reads is empty.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := runAWSSSO(cmd.ErrOrStderr(), "", []string{"sso", "logout"}); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Signed out of AWS SSO; the vault holds no AWS SSO login now.")
		return nil
	},
}

func init() {
	awsSSOCmd.Flags().StringVar(&awsSSOProfile, "profile", "", "the AWS profile to fetch credentials for (supplied by ~/.aws/config)")
	awsSSOCmd.AddCommand(awsSSOLogoutCmd)
	rootCmd.AddCommand(awsSSOCmd)
}

// awsSSORunBase is where run dirs live: jit's root, never $TMPDIR (D6).
func awsSSORunBase(root string) string { return filepath.Join(root, "aws-sso-run") }

// awsSSOBinary finds the real AWS CLI, skipping jit's shim dir.
var awsSSOBinary = func(home string) string {
	return wrap.RealBinary(home, os.Getenv("PATH"), "aws")
}

// runAWSSSO runs the AWS CLI with args on the unsealed login and returns
// its stdout. profile names the profile for error messages ("" for logout).
func runAWSSSO(stderr io.Writer, profile string, args []string) ([]byte, error) {
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
	return awsSSOWithLogin(stderr, v, home, root, awsBin, profile, args)
}

// awsSSOWithLogin is runAWSSSO's core, with the vault and the AWS CLI
// supplied, so a test can drive it with a stand-in CLI.
func awsSSOWithLogin(stderr io.Writer, v *vault.Vault, home, root, awsBin, profile string, args []string) ([]byte, error) {
	// One run at a time (D4): the refresh rotates the token, and two runs
	// refreshing together would both present the same one.
	unlock, err := lockAWSSSO(root)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	defer unlock()

	if _, err := migrate.CaptureAWSSSOLogin(v, home); err != nil {
		return nil, fmt.Errorf("jit aws-sso: sealing the login aws sso login just wrote: %w", err)
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
	_, _ = sealstore.Sweep(base, gcloudRunOwnerAlive)
	start, _ := lineage.ProcessStartTime(int32(os.Getpid())) // #nosec G115 -- a pid always fits in int32 on darwin
	runDir, err := sealstore.NewRunDir(base, os.Getpid(), start)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	defer func() { _ = os.RemoveAll(runDir) }()
	ssoDir := filepath.Join(runDir, ".aws", "sso")
	if err := os.MkdirAll(ssoDir, 0o700); err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}
	if len(blob) > 0 {
		if err := migrate.AWSSSOLayout.Unpack(blob, ssoDir); err != nil {
			return nil, fmt.Errorf("jit aws-sso: %w", err)
		}
	}
	baseline, err := migrate.AWSSSOLayout.Pack(ssoDir)
	if err != nil {
		return nil, fmt.Errorf("jit aws-sso: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), awsSSOTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, awsBin, args...) // #nosec G204 -- awsBin is the AWS CLI found on PATH; args are jit's own fixed command
	c.Env = awsSSOEnv(os.Environ(), runDir, migrate.AWSSSOSealedConfigPath(root))
	var stdout, errOut bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &errOut
	runErr := c.Run()

	// Reseal whatever the run left, success or not: a refresh that rotated
	// the token before a later step failed has still spent the old one.
	if after, err := migrate.AWSSSOLayout.Pack(ssoDir); err == nil && !bytes.Equal(after, baseline) {
		if err := migrate.StoreAWSSSOCache(v, home, after); err != nil {
			fmt.Fprintf(stderr, "jit aws-sso: could not seal the refreshed login: %v\n", err)
		}
	}
	if runErr != nil {
		return nil, awsSSOError(profile, errOut.String(), runErr)
	}
	return stdout.Bytes(), nil
}

// awsSSOEnv is the inner CLI's environment: the caller's, minus anything
// that would point it elsewhere, with HOME on the run dir (both of the
// CLI's caches resolve under it), the sealed config, and no shared
// credentials file. _AWS_CLI_PROFILE_CHAIN is export-credentials' loop
// guard: an outer `export-credentials --profile dev` sets it, and the inner
// run, resolving dev against the sealed config where dev IS the SSO
// profile, would refuse it as a cycle it is not (spike Result 2).
func awsSSOEnv(environ []string, runDir, sealedConfig string) []string {
	drop := []string{
		"HOME=", "AWS_CONFIG_FILE=", "AWS_SHARED_CREDENTIALS_FILE=", "_AWS_CLI_PROFILE_CHAIN=",
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
		strings.Contains(lower, "token has expired") || strings.Contains(lower, "refresh failed") {
		login := "aws sso login"
		if profile != "" {
			login += " --profile " + profile
		}
		return fmt.Errorf("jit aws-sso: no current AWS SSO login for this profile; run `%s` (jit seals it on the next use)", login)
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
