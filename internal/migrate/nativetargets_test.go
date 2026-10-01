// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestNativeTargetsNamesTheFileThatExists(t *testing.T) {
	home := t.TempDir()
	write := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []string{"aws", "terraform", "docker", "git", "kube"} {
		if got := NativeTargets(home, c); got != nil {
			t.Errorf("%s on an empty home = %v, want nothing", c, got)
		}
	}
	write(AWSCredentialsPath(home))
	write(DockerConfigPath(home))
	write(TerraformCredentialsPath(home))
	for c, want := range map[string]string{
		"aws": AWSCredentialsPath(home), "docker": DockerConfigPath(home), "terraform": TerraformCredentialsPath(home),
	} {
		if got := NativeTargets(home, c); !slices.Equal(got, []string{want}) {
			t.Errorf("%s = %v, want [%s]", c, got, want)
		}
	}
	// git: the XDG store file alone is named; with both, only the first,
	// since one discovery reads the two.
	write(GitCredentialsXDGPath(home))
	if got := NativeTargets(home, "git"); !slices.Equal(got, []string{GitCredentialsXDGPath(home)}) {
		t.Errorf("git with the XDG file = %v", got)
	}
	write(GitCredentialsPath(home))
	if got := NativeTargets(home, "git"); !slices.Equal(got, []string{GitCredentialsPath(home)}) {
		t.Errorf("git with both = %v, want ~/.git-credentials only", got)
	}
	// A directory where the file should be is not a file to name.
	dirHome := t.TempDir()
	if err := os.MkdirAll(AWSCredentialsPath(dirHome), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := NativeTargets(dirHome, "aws"); got != nil {
		t.Errorf("aws with a directory at the path = %v, want nothing", got)
	}
}
