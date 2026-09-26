// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// These are the refusals a jit outside JitPass.app gets on a vault whose key
// is in the Secure Enclave, which it can't reach. Whether it can is its
// signature's entitlement (secureenclave.Entitled, stubbed here through
// thisJitEntitled; secureenclave's TestThisBinarysEntitlement measures the
// real one). Every test runs against fakes: the key store is a stub,
// launchctl is a recording fake, HOME is a temp dir.

// testAppJit is the app's jit the refusals name (findAppJit, stubbed).
const testAppJit = "/Users/tester/Applications/JitPass.app/Contents/MacOS/jit"

// reachStore is a key store that answers Kind as told. It counts presence
// prompts, so a refusal that came after a Touch ID shows up as a count,
// never as a dialog, and presence lookups, so a check that asked the
// keychain shows up too: the service check must not (it answers
// Indeterminate, what a locked screen gives, if one ever does).
type reachStore struct {
	recordingStore
	r *reach
}

func (s reachStore) Presence() keystore.Presence { s.r.lookups++; return keystore.Indeterminate }

type countingPresence struct {
	*fakeKeyWrapper
	asked *int
}

func (p countingPresence) RequireUserPresence(string) error { *p.asked++; return nil }

func (s reachStore) NewWrapper() keystore.Wrapper {
	return countingPresence{newFakeKeyWrapper(), &s.r.asked}
}

// reach is one test's world: what the signature says and how often it was
// read, how many presence prompts and lookups ran, and how many times the
// app's jit was looked for.
type reach struct {
	entitled bool
	err      error
	checks   int
	asked    int
	lookups  int
	finds    int
}

// stubReach makes every key store this package opens answer kind (the
// store decides, as keystore.Open does in production: no sealed file is
// written, so a check that looked at the disk instead would see a keychain
// vault), makes this binary's signature answer entitled or err, and names
// testAppJit as the app's jit, counting the searches.
func stubReach(t *testing.T, kind keystore.Kind, entitled bool, err error) *reach {
	t.Helper()
	r := &reach{entitled: entitled, err: err}
	origStore, origEnt, origApp := openKeyStore, thisJitEntitled, findAppJit
	openKeyStore = func(string) keystore.Store {
		return reachStore{recordingStore{kind: kind, deleted: &[]keystore.Kind{}}, r}
	}
	thisJitEntitled = func() (bool, error) { r.checks++; return r.entitled, r.err }
	findAppJit = func() string { r.finds++; return testAppJit }
	t.Cleanup(func() { openKeyStore, thisJitEntitled, findAppJit = origStore, origEnt, origApp })
	return r
}

// recordLaunchctl fakes the launchctl seam, recording every call.
func recordLaunchctl(t *testing.T) *[][]string {
	t.Helper()
	calls := &[][]string{}
	orig, origWait := launchctlRun, agentStartWait
	launchctlRun = func(args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		return nil, nil
	}
	agentStartWait = 10 * time.Millisecond
	t.Cleanup(func() { launchctlRun, agentStartWait = orig, origWait })
	return calls
}

// plantAppPlist writes a login item that runs the jit inside JitPass.app,
// as the owner's does, and returns its path and bytes.
func plantAppPlist(t *testing.T) (string, []byte) {
	t.Helper()
	return plantPlist(t, testAppJit)
}

// plantPlist writes a login item that runs program.
func plantPlist(t *testing.T, program string) (string, []byte) {
	t.Helper()
	path, err := agentPlistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(fmt.Sprintf(agentPlistTemplate, agentPlistLabel, xmlEscape(program), "5m0s", "\n\t\t<string>--consent</string>", "/tmp/agent.log", "/tmp/agent.log"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func needsAppWords(command string) string {
	return "this vault's key is in the Secure Enclave,\n" +
		"and only the jit inside JitPass.app can reach it; run it from there:\n" +
		"`" + testAppJit + " " + command + "`"
}

// `jit service restart`, `ttl` and `consent`, run by a jit that can't reach
// the enclave on an enclave vault, refuse, name the jit inside JitPass.app
// and the command the user ran, and leave the login item exactly as it
// was: no plist write, no launchctl call, and (consent off) no Touch ID
// before the refusal. The signature is read once per command.
func TestServiceRefusesAJitThatCantReachTheEnclave(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		command string
		self    bool // the login item already runs this jit: restart's plain reload
	}{
		{[]string{"service", "restart"}, "service restart", false},
		{[]string{"service", "restart"}, "service restart", true},
		{[]string{"service", "ttl", "10m"}, "service ttl 10m", false},
		{[]string{"service", "consent", "on"}, "service consent on", false},
		{[]string{"service", "consent", "off"}, "service consent off", false},
	} {
		name := tc.command
		if tc.self {
			name += ", login item runs this jit"
		}
		t.Run(name, func(t *testing.T) {
			withFixtureHome(t)
			// A secret, so consent off's Touch ID goes through the stub
			// store (a count), never keychainwrap.Challenge (a dialog).
			seedFixtureVault(t, "fixture/API_KEY")
			r := stubReach(t, keystore.KindSecureEnclave, false, nil)
			calls := recordLaunchctl(t)
			plist, before := plantAppPlist(t)
			if tc.self {
				self, err := agentBinaryPath()
				if err != nil {
					t.Fatal(err)
				}
				plist, before = plantPlist(t, self)
			}

			out, err := runRoot(t, "", tc.args...)
			if r.asked != 0 {
				t.Errorf("Touch ID asked %d times before the refusal", r.asked)
			}
			want := "jit " + strings.Fields(tc.command)[0] + " " + strings.Fields(tc.command)[1] + ": " + needsAppWords(tc.command)
			if err == nil || err.Error() != want {
				t.Fatalf("got %v\nwant %s\n%s", err, want, out)
			}
			if r.checks != 1 || r.finds != 1 {
				t.Errorf("the signature was read %d times and the app's jit looked for %d, want once each per command", r.checks, r.finds)
			}
			if r.lookups != 0 {
				t.Errorf("the check asked the keychain %d times", r.lookups)
			}
			assertShortLines(t, strings.ReplaceAll(err.Error(), testAppJit+" "+tc.command, ""))
			if after, _ := os.ReadFile(plist); !bytes.Equal(after, before) {
				t.Errorf("the login item changed:\n%s", after)
			}
			if len(*calls) != 0 {
				t.Errorf("launchctl ran: %v", *calls)
			}
			if strings.Contains(out, "Touch ID") || strings.Contains(out, "Restarted") || strings.Contains(out, "set to") {
				t.Errorf("printed success:\n%s", out)
			}
		})
	}
}

// The controls, and the findings behind them: the check reads the binary's
// signature, never the keychain (no presence lookup, in any case), and
// takes the vault's kind from the key store (openKeyStore(root).Kind()),
// not from its own look at the disk. An entitled jit (the app's) goes on;
// a keychain vault goes on without reading the signature at all, a sealed
// file on disk or not. Refused: an unentitled jit on an enclave vault, and
// a signature that can't be read, each naming its cause. Where the check
// lets the command through, restart repoints the login item at this binary:
// the change the refusal exists to stop.
func TestServiceCheckDecidesFromTheSignature(t *testing.T) {
	unreadable := errors.New("SecTaskCreateFromSelf failed")
	for _, tc := range []struct {
		name         string
		kind         keystore.Kind
		entitled     bool
		entErr       error
		sealedOnDisk bool // a sealed file the store's answer overrides
		checks       int
		finds        int
		refuse       string
	}{
		{"entitled", keystore.KindSecureEnclave, true, nil, false, 1, 0, ""},
		{"entitled, sealed file on disk", keystore.KindSecureEnclave, true, nil, true, 1, 0, ""},
		{"keychain vault, unentitled", keystore.KindKeychain, false, nil, false, 0, 0, ""},
		{"keychain vault, unentitled, a sealed file on disk", keystore.KindKeychain, false, nil, true, 0, 0, ""},
		{"keychain vault, unreadable signature", keystore.KindKeychain, false, unreadable, false, 0, 0, ""},
		{"enclave vault, unentitled, no sealed file on disk", keystore.KindSecureEnclave, false, nil, false, 1, 1,
			"jit service restart: " + needsAppWords("service restart")},
		{"unreadable signature", keystore.KindSecureEnclave, false, unreadable, false, 1, 0,
			"jit service restart: couldn't read this jit's own signature,\nso the service was left as it was:\nSecTaskCreateFromSelf failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureHome(t)
			r := stubReach(t, tc.kind, tc.entitled, tc.entErr)
			if tc.sealedOnDisk {
				root, _ := vaultRootDir()
				if err := os.MkdirAll(root, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			calls := recordLaunchctl(t)
			plist, before := plantAppPlist(t)
			out, err := runRoot(t, "", "service", "restart")
			if r.checks != tc.checks || r.finds != tc.finds {
				t.Errorf("the signature was read %d times and the app's jit looked for %d, want %d and %d", r.checks, r.finds, tc.checks, tc.finds)
			}
			if r.lookups != 0 {
				t.Errorf("the check asked the keychain %d times", r.lookups)
			}
			if tc.refuse != "" {
				if err == nil || err.Error() != tc.refuse {
					t.Fatalf("got %v\nwant %s", err, tc.refuse)
				}
				if after, _ := os.ReadFile(plist); !bytes.Equal(after, before) || len(*calls) != 0 {
					t.Fatalf("a refusal changed the login item or ran launchctl: %v", *calls)
				}
				return
			}
			var refusal serviceRefusal
			if errors.As(err, &refusal) {
				t.Fatalf("refused a jit that may run the service: %v\n%s", err, out)
			}
			if !ranVerb(*calls, "bootstrap") {
				t.Fatalf("never reached launchctl (err %v): %v", err, *calls)
			}
			// The test binary is not the plist's program, so restart
			// repointed it: the change the refusal exists to stop.
			if after, _ := os.ReadFile(plist); bytes.Equal(after, before) {
				t.Error("restart did not repoint the login item")
			}
		})
	}
}

func ranVerb(calls [][]string, verb string) bool {
	for _, c := range calls {
		if len(c) > 0 && c[0] == verb {
			return true
		}
	}
	return false
}

// Every path that writes the plist takes the command's one clearance; with
// none it changes nothing (the check can't be skipped by a new caller).
func TestInstallAgentServiceNeedsAClearance(t *testing.T) {
	withFixtureHome(t)
	calls := recordLaunchctl(t)
	if _, _, err := installAgentService(time.Minute, true, serviceCleared{}); err == nil {
		t.Fatal("installed with no clearance")
	}
	if _, err := restartServiceOntoCurrentBinary(serviceCleared{}); err == nil {
		t.Fatal("restarted with no clearance")
	}
	plist, _ := agentPlistPath()
	if _, err := os.Stat(plist); !os.IsNotExist(err) || len(*calls) != 0 {
		t.Fatalf("wrote a login item (%v) or ran launchctl %v", err, *calls)
	}
}

// The silent install every vault command may trigger (ensureAgentInstalled)
// installs nothing, and repoints no orphaned login item, from a jit that
// can't reach the enclave: its failure is swallowed, as every install
// failure there is.
func TestEnsureAgentInstalledLeavesAnEnclaveVaultsServiceAlone(t *testing.T) {
	t.Run("no login item", func(t *testing.T) {
		withFixtureHome(t)
		r := stubReach(t, keystore.KindSecureEnclave, false, nil)
		calls := recordLaunchctl(t)
		if did, _ := ensureAgentInstalled(); did {
			t.Fatal("installed the service")
		}
		// Nobody reads this refusal, so nothing looks for the app's jit.
		if r.finds != 0 {
			t.Errorf("looked for the app's jit %d times on the silent path", r.finds)
		}
		plist, _ := agentPlistPath()
		if _, err := os.Stat(plist); !os.IsNotExist(err) || len(*calls) != 0 {
			t.Fatalf("wrote a login item (%v) or ran launchctl %v", err, *calls)
		}
	})
	t.Run("orphaned login item", func(t *testing.T) {
		withFixtureHome(t)
		r := stubReach(t, keystore.KindSecureEnclave, false, nil)
		t.Cleanup(func() {
			if r.finds != 0 {
				t.Errorf("looked for the app's jit %d times on the silent path", r.finds)
			}
		})
		calls := recordLaunchctl(t)
		path, err := agentPlistPath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		before := []byte(fmt.Sprintf(agentPlistTemplate, agentPlistLabel, filepath.Join(t.TempDir(), "gone", "jit"), "5m0s", "", "/tmp/a.log", "/tmp/a.log"))
		if err := os.WriteFile(path, before, 0o600); err != nil {
			t.Fatal(err)
		}
		if did, _ := ensureAgentInstalled(); did {
			t.Fatal("repointed the service")
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(after, before) || len(*calls) != 0 {
			t.Fatalf("changed the login item or ran launchctl %v", *calls)
		}
	})
	t.Run("control: the app's jit installs", func(t *testing.T) {
		withFixtureHome(t)
		stubReach(t, keystore.KindSecureEnclave, true, nil)
		calls := recordLaunchctl(t)
		if did, _ := ensureAgentInstalled(); !did || !ranVerb(*calls, "bootstrap") {
			t.Fatalf("the app's jit didn't install the service: %v", *calls)
		}
	})
}

// fakeAppBundle makes <dir>/JitPass.app with its helper's jit and the
// Contents/MacOS/jit symlink to it, as the app ships, and returns both.
func fakeAppBundle(t *testing.T, dir string) (link, helper string) {
	t.Helper()
	app := filepath.Join(dir, "JitPass.app")
	helper = filepath.Join(app, "Contents", "Helpers", "JitPassAgent.app", "Contents", "MacOS", "jit")
	link = filepath.Join(app, "Contents", "MacOS", "jit")
	for _, d := range []string{filepath.Dir(helper), filepath.Dir(link)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../Helpers/JitPassAgent.app/Contents/MacOS/jit", link); err != nil {
		t.Fatal(err)
	}
	return link, helper
}

// `jit upgrade`'s service step, from a jit serviceNeedsApp refuses: the
// binary is upgraded, the service is left as it was, and the output never
// says "Done", promises a Touch ID or advises `jit service restart` (which
// this jit refuses too). It ends quietly only when this jit was refused for
// running outside the app AND the login item runs the app's jit, its
// signature checked (serviceRunsAppJit): a program inside a JitPass bundle
// that isn't signed as the app's jit gets the refusal, and so does any
// other refusal, whatever the login item runs. The control: a keychain
// vault gets the old ending.
func TestUpgradeLeavesAnEnclaveVaultsServiceAlone(t *testing.T) {
	withFixtureHome(t)
	calls := recordLaunchctl(t)
	self, err := agentBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	link, helper := fakeAppBundle(t, t.TempDir())
	verified := map[string]bool{}
	origVerify := verifyAppJit
	verifyAppJit = func(p string) error {
		if verified[p] {
			return nil
		}
		return errors.New("not signed as the app's jit")
	}
	t.Cleanup(func() { verifyAppJit = origVerify })
	noDone := func(t *testing.T, out string) {
		t.Helper()
		for _, bad := range []string{"Done", "Touch ID", "Run jit service restart", "Restarting service"} {
			if strings.Contains(out, bad) {
				t.Errorf("printed %q:\n%s", bad, out)
			}
		}
		assertShortLines(t, strings.ReplaceAll(out, testAppJit+" service restart", ""))
	}
	refusedWords := "Upgraded this jit to v9.9.9.\nThe service was not moved onto it:\n" +
		strings.ReplaceAll(needsAppWords("service restart"), "`", "") + "\n"

	// The login item runs another jit (a repoint), already this one (the
	// plain reload an in-place upgrade does), or a program inside a
	// JitPass bundle that is not signed as the app's jit: all are left
	// alone, and the refusal is printed, naming the app's jit once.
	r := stubReach(t, keystore.KindSecureEnclave, false, nil)
	for _, program := range []string{filepath.Join(t.TempDir(), "jit"), self, helper, link} {
		r.finds = 0
		plist, before := plantPlist(t, program)
		var out bytes.Buffer
		upgradeMoveService(&out, "v9.9.9")
		if out.String() != refusedWords {
			t.Fatalf("login item running %s, output:\n%s\nwant:\n%s", program, out.String(), refusedWords)
		}
		if r.finds != 1 {
			t.Errorf("login item running %s: looked for the app's jit %d times, want once", program, r.finds)
		}
		noDone(t, out.String())
		if after, _ := os.ReadFile(plist); !bytes.Equal(after, before) || len(*calls) != 0 {
			t.Fatalf("login item running %s: changed it or ran launchctl %v", program, *calls)
		}
	}

	// The login item runs the app's jit, signature checked, through the
	// Contents/MacOS link or the helper itself: nothing to put right, and
	// no search for the app's jit (the refusal is never shown).
	verified[link], verified[helper] = true, true
	for _, program := range []string{link, helper} {
		r.finds = 0
		plist, before := plantPlist(t, program)
		var out bytes.Buffer
		upgradeMoveService(&out, "v9.9.9")
		if want := "Upgraded this jit to v9.9.9. The service keeps running JitPass's jit.\n"; out.String() != want {
			t.Fatalf("login item running %s:\n%s\nwant:\n%s", program, out.String(), want)
		}
		if r.finds != 0 {
			t.Errorf("looked for the app's jit %d times for a refusal never shown", r.finds)
		}
		noDone(t, out.String())
		if after, _ := os.ReadFile(plist); !bytes.Equal(after, before) || len(*calls) != 0 {
			t.Fatalf("changed the app's login item or ran launchctl %v", *calls)
		}
	}

	// Any other refusal is printed, cause named, even with the login item
	// on the app's jit: only "outside the app" is put right by the app.
	stubReach(t, keystore.KindSecureEnclave, false, errors.New("SecTaskCreateFromSelf failed"))
	plantPlist(t, link)
	var out bytes.Buffer
	upgradeMoveService(&out, "v9.9.9")
	if !strings.HasPrefix(out.String(), "Upgraded this jit to v9.9.9.\nThe service was not moved onto it:\ncouldn't read this jit's own signature,") ||
		!strings.Contains(out.String(), "SecTaskCreateFromSelf failed") {
		t.Fatalf("an unreadable signature, the login item on the app's jit:\n%s", out.String())
	}
	noDone(t, out.String())

	stubReach(t, keystore.KindKeychain, false, nil)
	out.Reset()
	upgradeMoveService(&out, "v9.9.9")
	if !strings.Contains(out.String(), "Done. Upgraded to v9.9.9.") || !ranVerb(*calls, "bootstrap") {
		t.Fatalf("a keychain vault's upgrade lost its ending (launchctl %v):\n%s", *calls, out.String())
	}
}

// An upgrade that couldn't swap the binary tells the user how to finish;
// the service restart is left off where this jit would refuse it.
func TestUpgradeFinishNeverNamesARefusedCommand(t *testing.T) {
	withFixtureHome(t)
	stubReach(t, keystore.KindSecureEnclave, false, nil)
	if got := upgradeFinishCommand("/tmp/jit-v9", "/usr/local/bin/jit"); got != "sudo mv -f /tmp/jit-v9 /usr/local/bin/jit" {
		t.Errorf("enclave vault, unentitled: %q", got)
	}
	stubReach(t, keystore.KindKeychain, false, nil)
	if got := upgradeFinishCommand("/tmp/jit-v9", "/usr/local/bin/jit"); got != "sudo mv -f /tmp/jit-v9 /usr/local/bin/jit && jit service restart" {
		t.Errorf("keychain vault: %q", got)
	}
}

// Where the refusals find the app's jit, and that only a jit whose
// signature says it is the app's is ever named: the login item's program
// when it is inside a JitPass bundle, then /Applications, then
// ~/Applications, then Spotlight's index, last, skipping another volume, a
// Trash and build folders; else no path at all. Each is checked with
// verifyAppJit, faked here (TestAppJitRequirementOnRealSignatures checks
// the real one).
func TestAppJitSelection(t *testing.T) {
	withFixtureHome(t)
	origByID, origDirs, origVerify := appBundlesByID, appBundleDirs, verifyAppJit
	t.Cleanup(func() { appBundlesByID, appBundleDirs, verifyAppJit = origByID, origDirs, origVerify })
	var asked []string
	spotlight := []string{}
	appBundlesByID = func(id string) []string { asked = append(asked, id); return spotlight }
	dirs := []string{}
	appBundleDirs = func() []string { return dirs }
	verified := map[string]bool{}
	var checked []string
	verifyAppJit = func(p string) error {
		checked = append(checked, p)
		if verified[p] {
			return nil
		}
		return errors.New("not signed as the app's jit")
	}
	bundle := func() (dir, link, helper string) {
		dir = t.TempDir()
		link, helper = fakeAppBundle(t, dir)
		return filepath.Join(dir, "JitPass.app"), link, helper
	}

	// 1. The login item's program, verified.
	_, _, helper := bundle()
	plantPlist(t, helper)
	verified[helper] = true
	if got := appJitPath(); got != helper || len(asked) != 0 {
		t.Fatalf("login item inside JitPass.app, verified: %q (Spotlight asked %v), want %q", got, asked, helper)
	}
	// Not verified: never named, whatever its path says.
	verified[helper] = false
	if got := appJitPath(); got != "" {
		t.Fatalf("an unverified program inside a JitPass bundle was named: %q", got)
	}

	// 2. /Applications before ~/Applications, each verified.
	asked = nil
	apps, appsLink, _ := bundle()
	home, homeLink, _ := bundle()
	dirs = []string{apps, home}
	verified[appsLink], verified[homeLink] = true, true
	if got := appJitPath(); got != appsLink {
		t.Fatalf("/Applications first: %q, want %q", got, appsLink)
	}
	verified[appsLink] = false
	if got := appJitPath(); got != homeLink {
		t.Fatalf("~/Applications next: %q, want %q", got, homeLink)
	}
	if len(asked) != 0 {
		t.Fatalf("Spotlight was asked (%v) before the folders ran out", asked)
	}

	// 3. Spotlight last: never another volume, a Trash or a build folder,
	// even verified; the first verified copy elsewhere.
	verified[homeLink] = false
	var skipped []string
	for _, dir := range []string{".Trash", filepath.Join("DerivedData", "JitPass-x", "Build"), filepath.Join(".build", "release")} {
		parent := filepath.Join(t.TempDir(), dir)
		link, _ := fakeAppBundle(t, parent) // real, and verified: only the place rules it out
		verified[link] = true
		skipped = append(skipped, filepath.Join(parent, "JitPass.app"))
	}
	for _, app := range append([]string{"/Volumes/JitPass/JitPass.app", "/Volumes/Backup/Users/x/.Trashes/JitPass.app"}, skipped...) {
		if !notTheInstalledApp(app) {
			t.Errorf("%s was taken for the installed app", app)
		}
	}
	for _, app := range []string{"/Applications/JitPass.app", "/Users/x/Apps/JitPass.app", "/Users/x/Volumes/JitPass.app"} {
		if notTheInstalledApp(app) {
			t.Errorf("%s was ruled out", app)
		}
	}
	other, otherLink, _ := bundle()
	indexed, indexedLink, _ := bundle()
	verified[indexedLink] = true
	spotlight = append(append([]string{}, skipped...), other, indexed)
	checked = nil
	if got := appJitPath(); got != indexedLink {
		t.Fatalf("Spotlight: %q, want the first verified copy outside the skipped places, %q", got, indexedLink)
	}
	if len(asked) == 0 || asked[len(asked)-1] != "com.jitpass.app" {
		t.Fatalf("Spotlight asked for %v, want com.jitpass.app", asked)
	}
	for _, p := range checked {
		for _, app := range skipped {
			if p == bundleJit(app) {
				t.Errorf("checked %s, a copy Spotlight answers that is not the installed app", p)
			}
		}
	}
	_ = otherLink

	// 4. Nothing verifies: no path.
	spotlight = skipped
	if got := appJitPath(); got != "" {
		t.Fatalf("nothing verified: %q, want none", got)
	}
	e := needsAppJitError{sealed: true, command: "service restart"}
	want := "this vault's key is in the Secure Enclave,\nand only the jit inside JitPass.app can reach it; use that jit to run:\nservice restart"
	if e.Error() != want {
		t.Fatalf("no path:\n%s\nwant:\n%s", e.Error(), want)
	}
	assertShortLines(t, e.Error())
}

// The command a refusal names pastes as it reads: a path with a space is
// quoted. And the search behind it runs once, however often the refusal is
// read, and not at all when it isn't.
func TestNeedsAppJitQuotesThePathAndSearchesOnce(t *testing.T) {
	finds := 0
	orig := findAppJit
	findAppJit = func() string { finds++; return "/Users/a b/Applications/JitPass.app/Contents/MacOS/jit" }
	t.Cleanup(func() { findAppJit = orig })
	e := needsAppJitError{sealed: true, command: "service restart", app: &appJitLookup{}}
	if finds != 0 {
		t.Fatalf("searched %d times before the refusal was read", finds)
	}
	want := "this vault's key is in the Secure Enclave,\nand only the jit inside JitPass.app can reach it; run it from there:\n" +
		"`'/Users/a b/Applications/JitPass.app/Contents/MacOS/jit' service restart`"
	for i := 0; i < 2; i++ {
		if got := e.Error(); got != want {
			t.Fatalf("read %d:\n%s\nwant:\n%s", i+1, got, want)
		}
	}
	if finds != 1 {
		t.Fatalf("searched %d times for two reads, want once", finds)
	}
}

// The real check, on real signatures (read only: no keychain query, nothing
// run). /bin/ls is Apple's, under another identifier: refused. Where
// JitPass.app is installed (a developer's Mac; never CI), its helper and
// the Contents/MacOS/jit link to it pass, and fail against a keychain group
// the helper doesn't carry, so the entitlement clause is live.
func TestAppJitRequirementOnRealSignatures(t *testing.T) {
	if err := codesignAppJit("/bin/ls"); err == nil {
		t.Fatal("/bin/ls passed as the jit inside JitPass.app")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := codesignAppJit(self); err == nil {
		t.Fatal("this test binary passed as the jit inside JitPass.app")
	}
	const helper = "/Applications/JitPass.app/Contents/Helpers/JitPassAgent.app/Contents/MacOS/jit"
	if os.Getenv("CI") != "" || !isFile(helper) {
		t.Skip("JitPass.app is not installed here; the positive half needs it")
	}
	for _, p := range []string{helper, "/Applications/JitPass.app/Contents/MacOS/jit"} {
		if err := codesignAppJit(p); err != nil {
			t.Errorf("the installed app's jit failed: %v", err)
		}
	}
	// #nosec G204 -- a fixed system binary, the installed app's own path
	out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "-R", appJitRequirement(secureenclave.TeamID+".com.jitpass.other"), helper).CombinedOutput()
	if err == nil {
		t.Errorf("the helper passed a requirement naming a group it doesn't carry:\n%s", out)
	}
}

// `jit vault rekey --wrapper` from a jit that can't reach the enclave is
// refused FIRST: before the recovery-file rule (these vaults have no
// recovery file, so that rule would refuse otherwise), before any question,
// and before any keychain access (kcPresent) or dialog.
func TestVaultMoveRefusesFirstWhenTheEnclaveIsUnreachable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		start  func(*moveWorld)
		target string
		sealed bool
	}{
		{"into the enclave", (*moveWorld).startInKeychain, wrapperSecureEnclave, false},
		{"back to the keychain", (*moveWorld).startInEnclave, wrapperKeychain, true},
		{"removing a keychain copy", func(w *moveWorld) { w.startInEnclave(); w.kc = append([]byte(nil), w.mek...) }, wrapperSecureEnclave, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureHome(t)
			root := seedFixtureVault(t, "fixture/API_KEY")
			stubKeyStores(t)
			origApp := findAppJit
			findAppJit = func() string { return testAppJit }
			t.Cleanup(func() { findAppJit = origApp })
			w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32), reach: secureenclave.ErrUnavailable}
			tc.start(w)
			kcBefore := append([]byte(nil), w.kc...)
			orig := runMover
			runMover = func(string, io.Writer) *keyMover { return w.mover() }
			t.Cleanup(func() { runMover = orig; vaultRekeyWrapper = "" })

			out, err := runRoot(t, "y\n", "vault", "rekey", "--wrapper", tc.target)
			want := "jit vault rekey: only the jit inside JitPass.app can reach\n" +
				"the Secure Enclave; run it from there:\n`" + testAppJit + " vault rekey --wrapper " + tc.target + "`"
			if tc.sealed {
				want = "jit vault rekey: " + needsAppWords("vault rekey --wrapper "+tc.target)
			}
			if err == nil || err.Error() != want {
				t.Fatalf("got %v\nwant %s\n%s", err, want, out)
			}
			// The command to copy is the one line the house rule can't
			// shorten: a path, never wrapped or cut.
			assertShortLines(t, strings.ReplaceAll(err.Error(), testAppJit+" vault rekey --wrapper "+tc.target, ""))
			if strings.Contains(out, "[y/N]") {
				t.Errorf("asked before refusing:\n%s", out)
			}
			if w.presenceCalls != 0 || len(w.prompts) != 0 {
				t.Errorf("reached the keychain (%d checks) or a dialog %q before refusing", w.presenceCalls, w.prompts)
			}
			if exists(rekeyMarkerPath(root)) || exists(w.staged()) || exists(w.real()) != tc.sealed || !bytes.Equal(w.kc, kcBefore) {
				t.Error("the refusal changed the vault")
			}
		})
	}
}

// The controls for the move's check. A jit that reaches the enclave meets
// the move's own rules as before (here the recovery-file rule, the one the
// check must come in front of); a keychain vault moving "back" to the
// keychain has nothing to do and never asks the enclave; and a check that
// can't tell refuses rather than guessing.
func TestVaultMoveReachCheckControls(t *testing.T) {
	run := func(t *testing.T, w *moveWorld, target string) (string, error) {
		orig := runMover
		runMover = func(string, io.Writer) *keyMover { return w.mover() }
		t.Cleanup(func() { runMover = orig; vaultRekeyWrapper = "" })
		out, err := runRoot(t, "n\n", "vault", "rekey", "--wrapper", target)
		return out + w.out.String(), err
	}
	t.Run("reachable: the move's own rules", func(t *testing.T) {
		withFixtureHome(t)
		root := seedFixtureVault(t, "fixture/API_KEY")
		stubKeyStores(t)
		w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
		w.startInKeychain()
		_, err := run(t, w, wrapperSecureEnclave)
		if err == nil || !strings.Contains(err.Error(), "recovery file") || w.reachCalls != 1 {
			t.Fatalf("got %v after %d checks, want the recovery-file rule after one", err, w.reachCalls)
		}
	})
	t.Run("keychain vault, back to the keychain", func(t *testing.T) {
		withFixtureHome(t)
		root := seedFixtureVault(t, "fixture/API_KEY")
		stubKeyStores(t)
		w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32), reach: secureenclave.ErrUnavailable}
		w.startInKeychain()
		vaultRekeyYes = true
		t.Cleanup(func() { vaultRekeyYes = false })
		out, err := run(t, w, wrapperKeychain)
		if err != nil || !strings.Contains(out, "already in the keychain. Nothing to do.") || w.reachCalls != 0 {
			t.Fatalf("err %v, %d checks:\n%s", err, w.reachCalls, out)
		}
	})
	t.Run("couldn't tell", func(t *testing.T) {
		withFixtureHome(t)
		root := seedFixtureVault(t, "fixture/API_KEY")
		stubKeyStores(t)
		w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32), reach: errors.New("SecTaskCreateFromSelf failed")}
		w.startInEnclave()
		_, err := run(t, w, wrapperKeychain)
		want := "jit vault rekey: couldn't check whether this copy of jit can reach\nthe Secure Enclave (SecTaskCreateFromSelf failed). Nothing changed"
		if err == nil || err.Error() != want || len(w.prompts) != 0 || !exists(w.real()) {
			t.Fatalf("got %v, prompts %q; want %q with nothing changed", err, w.prompts, want)
		}
	})
}

// The production mover's reach check is the binary's signature
// (thisJitEntitled), not a keychain lookup: entitled reaches, unentitled
// is ErrUnavailable, and a signature that can't be read is its own cause.
func TestProductionMoverAsksTheSignature(t *testing.T) {
	unreadable := errors.New("SecTaskCreateFromSelf failed")
	for _, tc := range []struct {
		entitled bool
		err      error
		want     error
	}{
		{true, nil, nil},
		{false, nil, secureenclave.ErrUnavailable},
		{false, unreadable, unreadable},
	} {
		orig := thisJitEntitled
		thisJitEntitled = func() (bool, error) { return tc.entitled, tc.err }
		err := newKeyMover(t.TempDir(), io.Discard).seReachable()
		thisJitEntitled = orig
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("entitled %v, err %v: seReachable() = %v, want %v", tc.entitled, tc.err, err, tc.want)
		}
	}
}

// The grant key stores mark a Load error by what it proves: their own
// proven-gone answer as agent.ErrGrantKeyAbsent, their "can't be used right
// now" as agent.ErrGrantKeyNotNow (an enclave locked or this jit
// unentitled), and nothing else: an unmarked error stops a never-ask job.
func TestGrantKeyStoresMarkLoadErrorsByWhatTheyProve(t *testing.T) {
	gone := fmt.Errorf("no Secure Enclave key for grant j-1: %w", secureenclave.ErrNoGrantKey)
	if err := markLoad(gone, secureenclave.ErrNoGrantKey, secureenclave.NotNow); !errors.Is(err, agent.ErrGrantKeyAbsent) || !errors.Is(err, secureenclave.ErrNoGrantKey) {
		t.Fatalf("a gone key = %v, want ErrGrantKeyAbsent keeping its cause", err)
	}
	for _, notNow := range []error{
		fmt.Errorf("grant key: %w", secureenclave.ErrUnavailable),
		fmt.Errorf("grant key: %w", secureenclave.ErrLocked),
	} {
		if err := markLoad(notNow, secureenclave.ErrNoGrantKey, secureenclave.NotNow); !errors.Is(err, agent.ErrGrantKeyNotNow) || errors.Is(err, agent.ErrGrantKeyAbsent) || !errors.Is(err, notNow) {
			t.Errorf("%v: %v, want ErrGrantKeyNotNow keeping its cause", notNow, err)
		}
	}
	for _, other := range []error{
		errors.New("grant key: empty grant id"),
		errors.New("grant key: checking for the Secure Enclave key failed (OSStatus=-50)"),
	} {
		if err := markLoad(other, secureenclave.ErrNoGrantKey, secureenclave.NotNow); err != other {
			t.Errorf("%v was marked or changed: %v", other, err)
		}
	}
}
