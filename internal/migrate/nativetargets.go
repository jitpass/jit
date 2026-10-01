// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import "os"

// NativeTargets returns the files to name for `jit migrate <file> --only
// <category>` when a native wrap (`jit wrap aws`) delegates to category:
// the machine-wide file the category reads, when it exists. A directory
// target is walked for project files only, never these, which is why the
// delegation cannot simply name the home directory. Empty means there is
// nothing on this Mac for the category to protect.
//
// git's two store files are one discovery (DiscoverGitCredentials reads
// both), so only the first that exists is named; naming both would plan
// every host twice.
func NativeTargets(home, category string) []string {
	var candidates []string
	switch category {
	case "aws":
		candidates = []string{AWSCredentialsPath(home)}
	case "terraform":
		candidates = []string{TerraformCredentialsPath(home)}
	case "docker":
		candidates = []string{DockerConfigPath(home)}
	case "git":
		candidates = []string{GitCredentialsPath(home), GitCredentialsXDGPath(home)}
	}
	for _, p := range candidates {
		if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() {
			return []string{p}
		}
	}
	return nil
}
