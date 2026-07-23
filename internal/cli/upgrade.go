// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
)

// This file is `jit upgrade`: the one command that reproduces the manual
// "download the release tarball, verify it, drop the binary into place,
// restart the service" dance a user otherwise types by hand (curl | tar |
// mv | jit service restart). It is the only place in jit that reaches the
// network, and it does so ONLY when a human runs this command — jit stays
// local-first everywhere else. Every downloaded byte is checked against the
// release's published SHA-256 before it can replace the running binary; a
// mismatch aborts with the old binary untouched, because an unverified
// download replacing a secrets tool's own executable is exactly the
// supply-chain surface we refuse to open.

const (
	upgradeRepoOwner = "jitpass"
	upgradeRepoName  = "jit"
)

// upgradeAssetName is the release archive for this machine. goreleaser
// publishes only darwin/arm64 (see .goreleaser.yml — CGO + no Intel
// hardware to test on), so any other GOOS/GOARCH has no asset and upgrade
// sends the user to `go install` instead of guessing.
func upgradeAssetName() string {
	return fmt.Sprintf("jitpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

func upgradeLatestURL(asset string) string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/latest/download/%s", upgradeRepoOwner, upgradeRepoName, asset)
}

func upgradeChecksumsURL() string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/latest/download/checksums.txt", upgradeRepoOwner, upgradeRepoName)
}

func upgradeLatestPageURL() string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/latest", upgradeRepoOwner, upgradeRepoName)
}

var upgradeForce bool

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Download the latest release, verify it, and swap this binary + service onto it",
	Long: "Upgrades jit in place: fetches the latest published release, verifies its\n" +
		"SHA-256 against the release's checksums.txt, replaces the running jit binary,\n" +
		"and restarts the background service so it's immediately on the new build (no\n" +
		"waiting for the stale-binary poll).\n\n" +
		"Replaces the binary `jit` actually runs from (whatever `which jit` resolves to).\n" +
		"If that path isn't writable (e.g. /usr/local/bin), you'll be prompted for sudo\n" +
		"just for the move. Your vault and secrets are never touched.\n\n" +
		"Only the published darwin/arm64 release is fetched this way; on any other\n" +
		"platform, build from source with `go install github.com/jitpass/jit/cmd/jit@latest`.",
	Args:    cobra.NoArgs,
	GroupID: groupService,
	RunE:    runUpgrade,
}

func runUpgrade(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return fmt.Errorf("jit upgrade fetches the published darwin/arm64 release only; on %s/%s build from source: go install github.com/%s/%s/cmd/jit@latest",
			runtime.GOOS, runtime.GOARCH, upgradeRepoOwner, upgradeRepoName)
	}

	// The binary jit actually runs from — resolve symlinks so we replace the
	// real file, not a shim pointing at it.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jit upgrade: locating the running binary: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exePath); rerr == nil {
		exePath = resolved
	}

	client := &http.Client{Timeout: 60 * time.Second}
	ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
	defer cancel()

	current := agent.Version()
	latest, err := upgradeLatestTag(ctx, client)
	if err != nil {
		return fmt.Errorf("jit upgrade: checking the latest release: %w", err)
	}
	fmt.Fprintf(out, "Current: %s   Latest: %s\n", displayVersion(current), latest)

	if !upgradeForce && !versionNewer(latest, current) {
		fmt.Fprintf(out, "Already on the latest release (%s). Use --force to reinstall it anyway.\n", displayVersion(current))
		return nil
	}

	asset := upgradeAssetName()

	// Checksums first: a tiny file, and having the expected sum in hand before
	// the archive lands means verification is just a comparison, never a
	// second round-trip that could see a different release mid-publish.
	fmt.Fprintf(out, "Fetching checksums ...\n")
	sums, err := upgradeChecksums(ctx, client)
	if err != nil {
		return fmt.Errorf("jit upgrade: fetching checksums: %w", err)
	}
	want, ok := sums[asset]
	if !ok {
		return fmt.Errorf("jit upgrade: the latest release has no checksum entry for %s (published assets: %s)", asset, strings.Join(sortedKeys(sums), ", "))
	}

	tmpDir, err := os.MkdirTemp("", "jit-upgrade-")
	if err != nil {
		return fmt.Errorf("jit upgrade: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Fprintf(out, "Downloading %s ...\n", asset)
	archivePath := filepath.Join(tmpDir, asset)
	got, err := downloadToFile(ctx, client, upgradeLatestURL(asset), archivePath)
	if err != nil {
		return fmt.Errorf("jit upgrade: downloading %s: %w", asset, err)
	}

	fmt.Fprintf(out, "Verifying checksum ... ")
	if !strings.EqualFold(got, want) {
		fmt.Fprintln(out, "FAILED")
		return fmt.Errorf("jit upgrade: checksum mismatch for %s (expected %s, got %s); refusing to install an unverified binary", asset, want, got)
	}
	fmt.Fprintln(out, "ok")

	staged := filepath.Join(tmpDir, "jit")
	if err := extractBinaryFromTarGz(archivePath, "jit", staged); err != nil {
		return fmt.Errorf("jit upgrade: extracting jit from %s: %w", asset, err)
	}

	usedSudo, err := replaceBinary(exePath, staged)
	if err != nil {
		return fmt.Errorf("jit upgrade: replacing %s: %w", exePath, err)
	}
	if usedSudo {
		fmt.Fprintf(out, "Replaced %s (via sudo).\n", exePath)
	} else {
		fmt.Fprintf(out, "Replaced %s.\n", exePath)
	}

	// Move the service onto the just-installed binary now, rather than waiting
	// on the stale-binary poll. Best-effort: the upgrade itself succeeded even
	// if the restart hiccups, so a restart failure is a warning, not an error
	// that would wrongly imply the binary wasn't swapped.
	fmt.Fprintf(out, "Restarting service ... ")
	if err := restartServiceOntoCurrentBinary(); err != nil {
		fmt.Fprintln(out, "could not restart automatically")
		fmt.Fprint(out, hlCmds(fmt.Sprintf("  Run `jit service restart` to move the service onto %s (%s).\n", latest, err)))
	} else {
		fmt.Fprintf(out, "now on %s.\n", latest)
	}

	fmt.Fprintf(out, "Done. Upgraded to %s. The next vault use will prompt Touch ID.\n", latest)
	return nil
}

// upgradeLatestTag resolves the latest release's tag (e.g. "v0.41.0") from
// the /releases/latest web redirect rather than the GitHub API. The page URL
// 302-redirects to /releases/tag/<tag>; reading that Location avoids
// api.github.com's 60-requests-per-hour unauthenticated limit (a real 403 an
// upgrade command must not depend on), while the same host serves both.
func upgradeLatestTag(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upgradeLatestPageURL(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "jit-upgrade")
	// Capture the redirect instead of following it — the tag lives in the
	// Location header, and there's no reason to fetch the release page body.
	noFollow := &http.Client{
		Timeout: client.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("expected a redirect from %s, got %s", upgradeLatestPageURL(), resp.Status)
	}
	loc := resp.Header.Get("Location")
	tag := path.Base(loc)
	if loc == "" || !strings.Contains(loc, "/tag/") || tag == "" || tag == "." || tag == "/" {
		return "", fmt.Errorf("could not read a release tag from redirect %q (are there any published releases?)", loc)
	}
	return tag, nil
}

// upgradeChecksums downloads and parses the release's checksums.txt into a
// filename→hex-sha256 map. goreleaser writes one "<sha256>  <filename>" line
// per asset.
func upgradeChecksums(ctx context.Context, client *http.Client) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upgradeChecksumsURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "jit-upgrade")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %s fetching checksums.txt", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseChecksums(string(data))
}

// parseChecksums reads goreleaser's checksums.txt format: each non-empty
// line is "<hex sha256>  <filename>" (two-space separator, but any run of
// whitespace is tolerated). A basename is stored so a "*jit_..." (binary
// marker) or a path-prefixed name still keys on the asset filename.
func parseChecksums(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*") // some tools mark binary files with a leading '*'
		out[filepath.Base(name)] = strings.ToLower(fields[0])
	}
	if len(out) == 0 {
		return nil, errors.New("no checksum entries found")
	}
	return out, nil
}

// downloadToFile streams url into dest and returns the hex SHA-256 of what
// was written, so the caller verifies the exact bytes on disk (not a second,
// separately-hashed copy).
func downloadToFile(ctx context.Context, client *http.Client, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "jit-upgrade")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %s", resp.Status)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- dest is jit's own temp download path
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractBinaryFromTarGz writes the single tar entry named `name` from a
// gzipped tarball to dest, mode 0755. It walks entries rather than assuming
// position, and refuses anything but a regular file under that name.
func extractBinaryFromTarGz(archivePath, name, dest string) error {
	f, err := os.Open(archivePath) // #nosec G304 -- archivePath is jit's own temp download path
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%q not found in archive", name)
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != name {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%q in archive is not a regular file", name)
		}
		w, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G304 G302 -- dest is jit's own staged temp path; a binary must be executable
		if err != nil {
			return err
		}
		// Bound the copy so a doctored archive can't exhaust the disk; a jit
		// binary is a few MB, 200 MB is generous headroom.
		if _, err := io.Copy(w, io.LimitReader(tr, 200<<20)); err != nil {
			_ = w.Close()
			return err
		}
		return w.Close()
	}
}

// replaceBinary atomically swaps the file at target for the freshly-staged
// binary. When target's directory is writable it renames within that dir
// (atomic, no window where target is missing or half-written); when it isn't
// (a root-owned /usr/local/bin), it falls back to a single `sudo mv`, which
// prompts on the user's terminal. Reports whether sudo was used.
//
// macOS permits replacing a running executable's path — the current process
// keeps the inode it already exec'd — so upgrading the very binary that's
// running this code is safe.
func replaceBinary(target, staged string) (usedSudo bool, err error) {
	dir := filepath.Dir(target)
	if dirWritable(dir) {
		tmp := filepath.Join(dir, ".jit-upgrade.new")
		if err := copyFile(staged, tmp, 0o755); err != nil {
			return false, err
		}
		if err := os.Rename(tmp, target); err != nil {
			_ = os.Remove(tmp)
			return false, err
		}
		return false, nil
	}
	if err := sudoCommand("/bin/mv", "-f", staged, target).Run(); err != nil {
		return true, fmt.Errorf("sudo mv into %s: %w", target, err)
	}
	// mv preserves the staged file's 0755 mode; nothing more to do.
	return true, nil
}

// sudoCommand builds a sudo invocation wired to the user's terminal so its
// password prompt is visible and answerable. Callers pass a fixed jit-owned
// program and arguments (a binary path from os.Executable, a staged temp
// file) — never external input.
func sudoCommand(args ...string) *exec.Cmd {
	c := exec.Command("sudo", args...) // #nosec G204 -- fixed program + jit-owned paths (os.Executable / temp files), never external input
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c
}

// restartServiceOntoCurrentBinary points the launchd service at the binary
// now on disk. If the login item exists it's reloaded (bootout+bootstrap,
// re-exec'ing the new binary at the same path); if it's missing entirely
// (never installed, or currently a foreground `jit service run`), it's
// created. Shares installAgentService/reloadAgentService with `jit service
// restart` so the two can't drift.
func restartServiceOntoCurrentBinary() error {
	plistPath, err := agentPlistPath()
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(plistPath); errors.Is(statErr, os.ErrNotExist) {
		// No plist to preserve a setting from, so install with the defaults
		// (default TTL, consent on). An existing plist takes the reload branch
		// below, which keeps whatever consent state it already has baked in.
		if _, _, ierr := installAgentService(agentInstallDefaultTTL, true); ierr != nil {
			return ierr
		}
		return nil
	} else if statErr != nil {
		return statErr
	}
	if out, err := reloadAgentService(plistPath); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".jit-wtest-")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- src is jit's own staged temp binary
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- dst is jit's own staged path in the install dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// versionNewer reports whether latest is a strictly higher release than
// current, comparing dotted numeric components (leading "v" and any
// pre-release/build suffix ignored). A non-numeric or unparseable current
// (e.g. "dev", a `go build` "+dirty" tree) is treated as older than any real
// tag, so upgrade still offers the update rather than dead-ending.
func versionNewer(latest, current string) bool {
	return compareVersions(latest, current) > 0
}

func compareVersions(a, b string) int {
	av := versionParts(a)
	bv := versionParts(b)
	for i := 0; i < len(av) || i < len(bv); i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

// versionParts turns "v0.41.0", "0.41.0", "0.41.0+dirty" into [0 41 0].
// Stops at the first non-numeric component so a "-rc1"/"+dirty" suffix
// doesn't poison the comparison; an unparseable string yields nil (sorts
// before any real version).
func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	var parts []int
	for _, seg := range strings.Split(v, ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			break
		}
		parts = append(parts, n)
	}
	return parts
}

// displayVersion normalizes a version for printing next to a "vX.Y.Z" tag:
// the ldflags stamp is bare ("0.40.0"), release tags carry the "v", so give
// both the "v" for a consistent "Current: v0.40.0   Latest: v0.41.0".
func displayVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" {
		return "(dev build)"
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// small maps; a simple insertion keeps the import list lean
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

func init() {
	upgradeCmd.Flags().BoolVar(&upgradeForce, "force", false, "reinstall the latest release even if it matches the current version")
	rootCmd.AddCommand(upgradeCmd)
}
