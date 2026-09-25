// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/secureenclave"
)

// fakeBackend records where grant keys were made, loaded and deleted.
type fakeBackend struct {
	name      string
	have      map[string]bool
	calls     *[]string
	deleteErr error
	listErr   error
}

type fakeGrantKey struct{ agent.GrantKey }

func (f fakeBackend) Create(id string) (agent.GrantKey, error) {
	*f.calls = append(*f.calls, f.name+" create "+id)
	f.have[id] = true
	return fakeGrantKey{}, nil
}

func (f fakeBackend) Load(id string) (agent.GrantKey, error) {
	*f.calls = append(*f.calls, f.name+" load "+id)
	if !f.have[id] {
		return nil, os.ErrNotExist
	}
	return fakeGrantKey{}, nil
}

func (f fakeBackend) Present(id string) (bool, error) { return f.have[id], nil }

func (f fakeBackend) List() ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []string
	for id := range f.have {
		out = append(out, id)
	}
	return out, nil
}

func (f fakeBackend) Delete(id string) error {
	*f.calls = append(*f.calls, f.name+" delete "+id)
	delete(f.have, id)
	return f.deleteErr
}

func fakeGrantStore(t *testing.T, root string) (grantKeyStore, *[]string, fakeBackend, fakeBackend) {
	t.Helper()
	calls := &[]string{}
	kc := fakeBackend{name: "keychain", have: map[string]bool{}, calls: calls}
	se := fakeBackend{name: "enclave", have: map[string]bool{}, calls: calls}
	return grantKeyStore{root: root, keys: kc, enclave: se}, calls, kc, se
}

func TestNewGrantKeysGoWhereTheVaultKeyIs(t *testing.T) {
	root := t.TempDir()
	stubKeyStores(t)
	g, calls, _, _ := fakeGrantStore(t, root)
	if _, err := g.Create("g-1"); err != nil {
		t.Fatal(err)
	}
	plantSealedKeyFile(t, root)
	if _, err := g.Create("g-2"); err != nil {
		t.Fatal(err)
	}
	want := []string{"keychain create g-1", "enclave create g-2"}
	if len(*calls) != 2 || (*calls)[0] != want[0] || (*calls)[1] != want[1] {
		t.Fatalf("calls = %q, want %q", *calls, want)
	}
}

// A grant made before the vault moved still loads its keychain key.
func TestGrantKeysLoadFromWhereverTheyAre(t *testing.T) {
	g, calls, kc, se := fakeGrantStore(t, t.TempDir())
	kc.have["old"] = true
	se.have["new"] = true
	if _, err := g.Load("old"); err != nil {
		t.Fatalf("keychain-keyed grant: %v", err)
	}
	if _, err := g.Load("new"); err != nil {
		t.Fatalf("enclave-keyed grant: %v", err)
	}
	if (*calls)[0] != "keychain load old" || (*calls)[1] != "enclave load new" {
		t.Fatalf("calls = %q", *calls)
	}
}

// Revoking clears both places. A jit that cannot reach the enclave still
// clears the keychain, and says the enclave was unreachable rather than
// passing as a delete: a jit that could reach it may have made a key there
// (finding 5), and the agent must not report that key deleted.
func TestGrantKeysDeleteClearsBoth(t *testing.T) {
	g, calls, kc, se := fakeGrantStore(t, t.TempDir())
	kc.have["g"], se.have["g"] = true, true
	if err := g.Delete("g"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("calls = %q, want a delete in each", *calls)
	}
	se.deleteErr = secureenclave.ErrUnavailable
	g.enclave = se
	kc.have["g"] = true
	err := g.Delete("g")
	if !errors.Is(err, agent.ErrGrantKeyUnreachable) {
		t.Fatalf("an unreachable enclave passed as a delete: %v", err)
	}
	if kc.have["g"] {
		t.Fatal("an unreachable enclave stopped the keychain delete")
	}
	se.deleteErr = errors.New("boom")
	g.enclave = se
	if err := g.Delete("g"); err == nil {
		t.Fatal("a real enclave failure was swallowed")
	}
	_ = keystore.KindKeychain
}

// Plan C3: the target is the vault key's kind.
func TestGrantKeyMoverTargetFollowsTheVaultKey(t *testing.T) {
	root := t.TempDir()
	stubKeyStores(t)
	g, _, _, _ := fakeGrantStore(t, root)
	if w := g.TargetWrap(); w != agent.GrantWrapKeychain {
		t.Fatalf("keychain vault target %q", w)
	}
	plantSealedKeyFile(t, root)
	if w := g.TargetWrap(); w != agent.GrantWrapEnclave {
		t.Fatalf("enclave vault target %q", w)
	}
}

// A crashed move left a new key behind; the retry reuses it instead of being
// refused by Create's "already exists".
func TestGrantKeyMoverCreateReusesACrashedMovesKey(t *testing.T) {
	g, calls, _, se := fakeGrantStore(t, t.TempDir())
	se.have["g"] = true
	if _, err := g.CreateWrap("g", agent.GrantWrapEnclave); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0] != "enclave load g" {
		t.Fatalf("calls = %q, want a load of the existing key, not a create", *calls)
	}
}

func TestGrantKeyMoverDeleteToleratesAnUnreachableEnclave(t *testing.T) {
	g, _, _, se := fakeGrantStore(t, t.TempDir())
	se.deleteErr = secureenclave.ErrUnavailable
	g.enclave = se
	if err := g.DeleteWrap("g", agent.GrantWrapEnclave); err != nil {
		t.Fatalf("got %v", err)
	}
}

// Plan C4: the ids come from both places; an enclave this jit cannot reach
// adds none rather than failing the list.
func TestGrantKeyListerUnionsBothBackends(t *testing.T) {
	g, _, kc, se := fakeGrantStore(t, t.TempDir())
	kc.have["g-00000001"] = true
	se.have["j-00000002"] = true
	ids, err := g.ListGrantKeyIDs()
	if err != nil || len(ids) != 2 {
		t.Fatalf("ids %v, err %v", ids, err)
	}
	se.listErr = secureenclave.ErrUnavailable
	g.enclave = se
	if ids, err := g.ListGrantKeyIDs(); err != nil || len(ids) != 1 {
		t.Fatalf("unreachable enclave: ids %v, err %v", ids, err)
	}
	se.listErr = errors.New("boom")
	g.enclave = se
	if _, err := g.ListGrantKeyIDs(); err == nil {
		t.Fatal("a real enclave failure was swallowed; the service log should show it")
	}
}

// A revoke or a remove whose key was kept shows the service's note, one
// clause a line; one with no note shows nothing extra.
func TestPrintKeyNote(t *testing.T) {
	var b strings.Builder
	printKeyNote(&b, "")
	if b.Len() != 0 {
		t.Fatalf("an empty note printed %q", b.String())
	}
	printKeyNote(&b, "Its key couldn't be reached from this copy of jit; the service deletes it later.")
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "from this copy of jit;") || !strings.HasSuffix(lines[1], "the service deletes it later.") {
		t.Fatalf("printed %q", b.String())
	}
}
