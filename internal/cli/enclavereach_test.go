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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/secureenclave"
)

// These are the refusals a jit outside JitPass.app gets on a vault whose key
// is in the Secure Enclave, which it can't reach (no entitlement;
// secureenclave's TestUnsignedBinaryCannotReachTheEnclave measures what the
// real enclave answers such a binary). Every one runs against fakes: the
// key store is a stub, launchctl is a recording fake, HOME is a temp dir.

// reachStore is a key store that answers Kind and Presence as told and
// counts presence prompts, so a refusal that came after a Touch ID shows up
// as a count, never as a dialog.
type reachStore struct {
	recordingStore
	p     keystore.Presence
	asked *int
}

func (s reachStore) Presence() keystore.Presence { return s.p }

type countingPresence struct {
	*fakeKeyWrapper
	asked *int
}

func (p countingPresence) RequireUserPresence(string) error { *p.asked++; return nil }

func (s reachStore) NewWrapper() keystore.Wrapper {
	return countingPresence{newFakeKeyWrapper(), s.asked}
}

// stubReach makes every key store this package opens answer kind and p.
// It returns the count of presence prompts.
func stubReach(t *testing.T, kind keystore.Kind, p keystore.Presence) *int {
	t.Helper()
	asked := new(int)
	orig := openKeyStore
	openKeyStore = func(string) keystore.Store {
		return reachStore{recordingStore{kind: kind, deleted: &[]keystore.Kind{}}, p, asked}
	}
	t.Cleanup(func() { openKeyStore = orig })
	return asked
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
	return plantPlist(t, appJit)
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
		"`/Applications/JitPass.app/Contents/MacOS/jit " + command + "`"
}

// Item 1: `jit service restart`, `ttl` and `consent`, run by a jit that
// can't reach the enclave on an enclave vault, refuse, name the jit inside
// JitPass.app, and leave the login item exactly as it was: no plist write,
// no launchctl call, and (consent off) no Touch ID before the refusal.
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
			asked := stubReach(t, keystore.KindSecureEnclave, keystore.Unavailable)
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
			if *asked != 0 {
				t.Errorf("Touch ID asked %d times before the refusal", *asked)
			}
			want := "jit " + strings.Fields(tc.command)[0] + " " + strings.Fields(tc.command)[1] + ": " + needsAppWords(tc.command)
			if err == nil || err.Error() != want {
				t.Fatalf("got %v\nwant %s\n%s", err, want, out)
			}
			assertShortLines(t, strings.ReplaceAll(err.Error(), appJit+" "+tc.command, ""))
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

// The controls: a jit that reaches the enclave (Present, and KeyLost, which
// is the service's to report), or any keychain vault, goes on as before and
// reaches launchctl. And an enclave vault whose key jit couldn't look up
// fails closed.
func TestServiceCheckLetsAReachableJitThrough(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   keystore.Kind
		p      keystore.Presence
		refuse string
	}{
		{"enclave, reachable", keystore.KindSecureEnclave, keystore.Present, ""},
		{"enclave, key lost", keystore.KindSecureEnclave, keystore.KeyLost, ""},
		{"keychain vault", keystore.KindKeychain, keystore.Unavailable, ""},
		{"enclave, couldn't check", keystore.KindSecureEnclave, keystore.Indeterminate, "couldn't\ncheck whether this copy of jit can reach it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureHome(t)
			stubReach(t, tc.kind, tc.p)
			calls := recordLaunchctl(t)
			plist, before := plantAppPlist(t)
			out, err := runRoot(t, "", "service", "restart")
			if tc.refuse != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refuse) {
					t.Fatalf("got %v, want a refusal saying %q", err, tc.refuse)
				}
				if after, _ := os.ReadFile(plist); !bytes.Equal(after, before) || len(*calls) != 0 {
					t.Fatalf("a refusal changed the login item or ran launchctl: %v", *calls)
				}
				return
			}
			var needsApp needsAppJitError
			if errors.As(err, &needsApp) {
				t.Fatalf("refused a jit that can reach the key: %v\n%s", err, out)
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

// The silent install every vault command may trigger (ensureAgentInstalled)
// installs nothing, and repoints no orphaned login item, from a jit that
// can't reach the enclave: its failure is swallowed, as every install
// failure there is.
func TestEnsureAgentInstalledLeavesAnEnclaveVaultsServiceAlone(t *testing.T) {
	t.Run("no login item", func(t *testing.T) {
		withFixtureHome(t)
		stubReach(t, keystore.KindSecureEnclave, keystore.Unavailable)
		calls := recordLaunchctl(t)
		if did, _ := ensureAgentInstalled(); did {
			t.Fatal("installed the service")
		}
		plist, _ := agentPlistPath()
		if _, err := os.Stat(plist); !os.IsNotExist(err) || len(*calls) != 0 {
			t.Fatalf("wrote a login item (%v) or ran launchctl %v", err, *calls)
		}
	})
	t.Run("orphaned login item", func(t *testing.T) {
		withFixtureHome(t)
		stubReach(t, keystore.KindSecureEnclave, keystore.Unavailable)
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
}

// `jit upgrade`'s service step on an enclave vault it can't reach: the
// binary is upgraded, the service is left as it was, and the output never
// says "Done" or promises a Touch ID. The control: a keychain vault gets
// the old ending.
func TestUpgradeLeavesAnEnclaveVaultsServiceAlone(t *testing.T) {
	withFixtureHome(t)
	stubReach(t, keystore.KindSecureEnclave, keystore.Unavailable)
	calls := recordLaunchctl(t)
	self, err := agentBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	// The login item runs the app's jit (a repoint), or already this one
	// (the plain reload an in-place upgrade does): both are left alone.
	for _, program := range []string{appJit, self} {
		plist, before := plantPlist(t, program)
		var out bytes.Buffer
		upgradeMoveService(&out, "v9.9.9")
		want := "Restarting service ... left as it was:\n" +
			strings.ReplaceAll(needsAppWords("service restart"), "`", "") + "\n" +
			"Upgraded this jit to v9.9.9. The service was not moved onto it.\n"
		if out.String() != want {
			t.Fatalf("login item running %s, output:\n%s\nwant:\n%s", program, out.String(), want)
		}
		assertShortLines(t, strings.ReplaceAll(out.String(), appJit+" service restart", ""))
		if after, _ := os.ReadFile(plist); !bytes.Equal(after, before) || len(*calls) != 0 {
			t.Fatalf("login item running %s: changed it or ran launchctl %v", program, *calls)
		}
	}

	stubReach(t, keystore.KindKeychain, keystore.Present)
	var out bytes.Buffer
	upgradeMoveService(&out, "v9.9.9")
	if !strings.Contains(out.String(), "Done. Upgraded to v9.9.9.") || !ranVerb(*calls, "bootstrap") {
		t.Fatalf("a keychain vault's upgrade lost its ending (launchctl %v):\n%s", *calls, out.String())
	}
}

// Item 2: `jit vault rekey --wrapper` from a jit that can't reach the
// enclave is refused FIRST: before the recovery-file rule (these vaults
// have no recovery file, so that rule would refuse otherwise), before any
// question, and before any keychain access (kcPresent) or dialog.
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
			w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32), reach: secureenclave.ErrUnavailable}
			tc.start(w)
			kcBefore := append([]byte(nil), w.kc...)
			orig := runMover
			runMover = func(string, io.Writer) *keyMover { return w.mover() }
			t.Cleanup(func() { runMover = orig; vaultRekeyWrapper = "" })

			out, err := runRoot(t, "y\n", "vault", "rekey", "--wrapper", tc.target)
			want := "jit vault rekey: only the jit inside JitPass.app can reach\n" +
				"the Secure Enclave; run it from there:\n`/Applications/JitPass.app/Contents/MacOS/jit vault rekey --wrapper " + tc.target + "`"
			if tc.sealed {
				want = "jit vault rekey: " + needsAppWords("vault rekey --wrapper "+tc.target)
			}
			if err == nil || err.Error() != want {
				t.Fatalf("got %v\nwant %s\n%s", err, want, out)
			}
			// The command to copy is the one line the house rule can't
			// shorten: a path, never wrapped or cut.
			assertShortLines(t, strings.ReplaceAll(err.Error(), appJit+" vault rekey --wrapper "+tc.target, ""))
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
		w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32), reach: errors.New("a lookup that failed")}
		w.startInEnclave()
		_, err := run(t, w, wrapperKeychain)
		want := "jit vault rekey: couldn't check whether this copy of jit can reach\nthe Secure Enclave (a lookup that failed). Nothing changed"
		if err == nil || err.Error() != want || len(w.prompts) != 0 || !exists(w.real()) {
			t.Fatalf("got %v, prompts %q; want %q with nothing changed", err, w.prompts, want)
		}
	})
}

// The grant key stores mark only their own proven-gone answer as
// agent.ErrGrantKeyAbsent, the one Load error that stops a never-ask job
// for good; an enclave this jit can't reach is not "gone".
func TestGrantKeyStoresMarkOnlyAProvenGoneKeyAbsent(t *testing.T) {
	gone := fmt.Errorf("no Secure Enclave key for grant j-1: %w", secureenclave.ErrNoGrantKey)
	if err := absentAs(gone, secureenclave.ErrNoGrantKey); !errors.Is(err, agent.ErrGrantKeyAbsent) || !errors.Is(err, secureenclave.ErrNoGrantKey) {
		t.Fatalf("a gone key = %v, want ErrGrantKeyAbsent keeping its cause", err)
	}
	for _, other := range []error{
		fmt.Errorf("grant key: %w", secureenclave.ErrUnavailable),
		fmt.Errorf("grant key: %w", secureenclave.ErrLocked),
		errors.New("grant key: empty grant id"),
	} {
		if err := absentAs(other, secureenclave.ErrNoGrantKey); errors.Is(err, agent.ErrGrantKeyAbsent) || err != other {
			t.Errorf("%v was marked or changed: %v", other, err)
		}
	}
}
