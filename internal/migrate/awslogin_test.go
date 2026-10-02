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

const (
	devSession   = "arn:aws:iam::111122223333:user/dev"
	otherSession = "arn:aws:iam::444455556666:user/other"
)

// awsLoginHome is a home with two `aws login` profiles and their sessions.
func awsLoginHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	files := map[string]string{
		AWSConfigPath(home):                   "[profile dev]\nlogin_session = " + devSession + "\nregion = us-east-1\n\n[profile other]\nlogin_session = " + otherSession + "\nregion = eu-west-1\n",
		AWSLoginCacheFile(home, devSession):   `{"accessToken":{"accessKeyId":"ASIA1"},"refreshToken":"rt-dev","dpopKey":"k","clientId":"c"}`,
		AWSLoginCacheFile(home, otherSession): `{"accessToken":{"accessKeyId":"ASIA2"},"refreshToken":"rt-other","dpopKey":"k","clientId":"c"}`,
	}
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// Sealing one `aws login` profile takes in its session and nothing else:
// another profile's session is still read from disk by that profile, so it
// stays. The profile loses login_session (what makes botocore's login
// provider claim it) for credential_process, and says how to sign in.
func TestApplyAWSSSOSealsAnAWSLoginProfile(t *testing.T) {
	home := awsLoginHome(t)
	v := newTestVault(t)
	t.Cleanup(SetJitExecutableForTesting("/usr/local/bin/jit"))
	found, err := DiscoverAWSSSOProfiles(home)
	if err != nil || !reflect.DeepEqual(found, []string{"dev", "other"}) {
		t.Fatalf("discovered %q, %v", found, err)
	}
	res, err := ApplyAWSSSO(v, home, []string{"dev"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.LoginProfiles, []string{"dev"}) || !reflect.DeepEqual(res.CacheFiles, []string{AWSLoginCacheFile(home, devSession)}) {
		t.Fatalf("login profiles %q, cache files %q", res.LoginProfiles, res.CacheFiles)
	}
	if _, err := os.Stat(AWSLoginCacheFile(home, devSession)); !os.IsNotExist(err) {
		t.Fatal("dev's session is still on disk")
	}
	if _, err := os.Stat(AWSLoginCacheFile(home, otherSession)); err != nil {
		t.Fatalf("other's session was taken: %v", err)
	}
	cfg, _ := os.ReadFile(AWSConfigPath(home)) // #nosec G304 -- test path
	dev := string(cfg[:strings.Index(string(cfg), "[profile other]")])
	if strings.Contains(dev, "login_session") || !strings.Contains(dev, "credential_process = /usr/local/bin/jit aws-sso --profile dev") ||
		!strings.Contains(dev, "# jit: this login is sealed in the vault; log in again with `jit aws-sso login --profile dev`") {
		t.Fatalf("dev after sealing:\n%s", dev)
	}
	if !strings.Contains(string(cfg), "login_session = "+otherSession) {
		t.Fatalf("other was rewritten:\n%s", cfg)
	}
	sealed, _ := os.ReadFile(AWSSSOSealedConfigPath(v.Root)) // #nosec G304 -- test path
	if !strings.Contains(string(sealed), "login_session = "+devSession) || strings.Contains(string(sealed), otherSession) {
		t.Fatalf("sealed config:\n%s", sealed)
	}
	if in, _ := AWSSSOSignedIn(v.Root); !in {
		t.Fatal("a sealed `aws login` session reads as signed out")
	}

	// Sealing it again changes nothing, the comment included.
	if again, _ := DiscoverAWSSSOProfiles(home); !reflect.DeepEqual(again, []string{"other"}) {
		t.Fatalf("rediscovered %q", again)
	}

	// The session comes back from the vault on undo, the other untouched.
	if err := os.Remove(AWSLoginCacheFile(home, otherSession)); err != nil {
		t.Fatal(err)
	}
	written, err := UnsealAWSSSOCache(v, home, true)
	if err != nil || !reflect.DeepEqual(written, []string{AWSLoginCacheFile(home, devSession)}) {
		t.Fatalf("unsealed %q, %v", written, err)
	}
}

// A session in ~/.aws/login/cache is never captured: `aws login` cannot
// sign in a sealed profile, so the session is an unsealed profile's, and
// that profile reads it from there.
func TestCaptureLeavesAWSLoginSessions(t *testing.T) {
	home := awsLoginHome(t)
	v := newTestVault(t)
	captured, err := CaptureAWSSSOLogin(v, home)
	if err != nil || captured {
		t.Fatalf("captured %v, %v", captured, err)
	}
	if _, err := os.Stat(AWSLoginCacheFile(home, devSession)); err != nil {
		t.Fatalf("the session went: %v", err)
	}
}

func TestAWSSealedLoginArgs(t *testing.T) {
	root := t.TempDir()
	if _, err := AWSSealedLoginArgs(root, "dev", false); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("nothing sealed: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(AWSSSOSealedConfigPath(root)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(AWSSSOSealedConfigPath(root), []byte("[profile web]\nlogin_session = "+devSession+"\n\n[profile sso]\nsso_session = corp\nsso_account_id = 1\n\n[sso-session corp]\nsso_start_url = https://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		profile string
		remote  bool
		want    string
	}{
		{"web", false, "login --profile web"},
		{"web", true, "login --profile web --remote"},
		{"sso", false, "sso login --profile sso"},
		{"sso", true, "sso login --profile sso --use-device-code"},
	} {
		got, err := AWSSealedLoginArgs(root, c.profile, c.remote)
		if err != nil || strings.Join(got, " ") != c.want {
			t.Errorf("%s remote=%v: %q, %v", c.profile, c.remote, got, err)
		}
	}
	if _, err := AWSSealedLoginArgs(root, "nope", false); err == nil {
		t.Fatal("an unknown profile got a sign-in")
	}
}
