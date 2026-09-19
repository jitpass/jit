// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func launchProfiles(l []ProfileLaunch) string {
	var parts []string
	for _, x := range l {
		parts = append(parts, x.Detail+"="+x.Profile)
	}
	return strings.Join(parts, ",")
}

func TestAWSConfigProfileLaunches(t *testing.T) {
	home := t.TempDir()
	if got, err := AWSConfigProfileLaunches(home); err != nil || got != nil {
		t.Fatalf("no ~/.aws/config = (%v, %v), want (nil, nil)", got, err)
	}
	writeFile(t, AWSConfigPath(home), `[default]
region = us-east-1
credential_process = /opt/homebrew/bin/jit aws-credential-process --profile aws-default

[profile dev]
region = us-east-1

credential_process = /opt/homebrew/bin/jit aws-credential-process --profile aws-dev

[profile spaced]
credential_process = "/Users/x/My Tools/jit" aws-credential-process --profile=aws-spaced

[profile other]
credential_process = aws-vault exec --profile other --json

# [profile commented]
# credential_process = /opt/homebrew/bin/jit aws-credential-process --profile aws-commented
`)
	got, err := AWSConfigProfileLaunches(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := "[default]=aws-default,[profile dev]=aws-dev,[profile spaced]=aws-spaced"; launchProfiles(got) != want {
		t.Errorf("launches = %s, want %s", launchProfiles(got), want)
	}
	if got[1].Line != 8 || got[1].File != AWSConfigPath(home) {
		t.Errorf("dev launch = %+v, want line 8 of %s", got[1], AWSConfigPath(home))
	}
}

func TestKubeconfigProfileLaunches(t *testing.T) {
	home := t.TempDir()
	if got, err := KubeconfigProfileLaunches(home); err != nil || got != nil {
		t.Fatalf("no kubeconfig = (%v, %v), want (nil, nil)", got, err)
	}
	writeFile(t, KubeconfigPath(home), `apiVersion: v1
users:
- name: docker-desktop
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /opt/homebrew/bin/jit
      args: [k8s-exec-credential, --profile, k8s-docker-desktop]
- name: gke
  user:
    exec:
      command: gke-gcloud-auth-plugin
      args: [--profile, not-jit]
- name: plain
  user:
    token: abc
`)
	got, err := KubeconfigProfileLaunches(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := "user docker-desktop=k8s-docker-desktop"; launchProfiles(got) != want {
		t.Errorf("launches = %s, want %s", launchProfiles(got), want)
	}
	writeFile(t, KubeconfigPath(home), "users: [unterminated")
	if _, err := KubeconfigProfileLaunches(home); err == nil {
		t.Error("an unparseable kubeconfig must be an error, not an empty answer")
	}
}

func TestShellRCProfileLaunches(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".zshrc"), `export PATH="$HOME/bin:$PATH"
`+jitShellComment+`
eval "$(jit export --profile zshrc)"
# eval "$(jit export --profile disabled)"
eval "$(/opt/homebrew/bin/jit export --profile=work.env)"
source <(jit completion zsh)
`)
	writeFile(t, filepath.Join(home, ".bash_profile"), `eval "$(jit export --profile bash_profile)"`+"\n")
	got, err := ShellRCProfileLaunches(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := "line 3=zshrc,line 5=work.env,line 1=bash_profile"; launchProfiles(got) != want {
		t.Errorf("launches = %s, want %s", launchProfiles(got), want)
	}

	// What ApplyShellConfig writes is what this reads.
	lines := rewriteShellConfigLines([]string{"export API_TOKEN=abc"}, map[int]bool{0: true}, "profile_x")
	writeFile(t, filepath.Join(home, ".zshrc"), strings.Join(lines, "\n"))
	got, _ = ShellRCProfileLaunches(home)
	if len(got) == 0 || got[0].Profile != "profile_x" {
		t.Errorf("the writer's own line was not read back: %+v", got)
	}
}

// One unreadable rc file is an error, and the others are still read.
func TestShellRCProfileLaunchesUnreadable(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".zshrc"), `eval "$(jit export --profile zshrc)"`)
	bad := filepath.Join(home, ".bashrc")
	writeFile(t, bad, `eval "$(jit export --profile bashrc)"`)
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	got, err := ShellRCProfileLaunches(home)
	if err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("err = %v, want one naming %s", err, bad)
	}
	if launchProfiles(got) != "line 1=zshrc" {
		t.Errorf("launches = %s, want the readable file's", launchProfiles(got))
	}
}

func TestSplitCommandLine(t *testing.T) {
	for in, want := range map[string][]string{
		`/opt/jit aws-credential-process --profile aws-dev`:         {"/opt/jit", "aws-credential-process", "--profile", "aws-dev"},
		`"/My Tools/jit" aws-credential-process --profile "a b"`:    {"/My Tools/jit", "aws-credential-process", "--profile", "a b"},
		`'/x y/jit'  run   --profile p`:                             {"/x y/jit", "run", "--profile", "p"},
		`"say \"hi\"" x`:                                            {`say "hi"`, "x"},
		`'unterminated`:                                             {"unterminated"},
		quoteIfNeeded("/Has Space/jit") + " aws-credential-process": {"/Has Space/jit", "aws-credential-process"},
	} {
		if got := splitCommandLine(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitCommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}
