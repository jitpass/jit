// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/sealstore"
)

// msal builds an MSAL token cache: one account per name, each with a
// refresh token whose secret is given.
func msal(t *testing.T, accounts map[string]string) []byte {
	t.Helper()
	cache := map[string]map[string]any{"Account": {}, "RefreshToken": {}}
	for name, rt := range accounts {
		cache["Account"][name+"-account"] = map[string]string{"username": name}
		cache["RefreshToken"][name+"-refreshtoken"] = map[string]string{"secret": rt}
	}
	b, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func store(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	b, err := sealstore.PackFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func refreshTokens(t *testing.T, blob []byte) map[string]string {
	t.Helper()
	files, err := sealstore.Files(blob)
	if err != nil {
		t.Fatal(err)
	}
	var cache struct {
		RefreshToken map[string]struct{ Secret string } `json:"RefreshToken"`
	}
	if data := files["msal_token_cache.json"]; data != nil {
		if err := json.Unmarshal(data, &cache); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string]string{}
	for k, v := range cache.RefreshToken {
		out[strings.TrimSuffix(k, "-refreshtoken")] = v.Secret
	}
	return out
}

// The case the merge exists for: run A refreshes (its refresh token
// rotates) while run B signs in a second account and seals first. A's
// reseal must keep B's login and still take A's rotated token.
func TestMergeAzureStoreKeepsAConcurrentLogin(t *testing.T) {
	base := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1"})})
	current := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops"})})
	after := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-2"})})
	merged, err := MergeAzureStore(base, current, after)
	if err != nil {
		t.Fatal(err)
	}
	got := refreshTokens(t, merged)
	if got["dev"] != "rt-2" || got["ops"] != "rt-ops" || len(got) != 2 {
		t.Fatalf("merged refresh tokens %v, want dev rt-2 and ops rt-ops", got)
	}
}

// A sign-out removes what the run removed and nothing another run added;
// a store left with no entry at all is no file, as az leaves it.
func TestMergeAzureStoreSignOut(t *testing.T) {
	base := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1"})})
	current := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops"})})
	cleared := store(t, map[string][]byte{}) // `az account clear` deleted the file
	merged, err := MergeAzureStore(base, current, cleared)
	if err != nil {
		t.Fatal(err)
	}
	if got := refreshTokens(t, merged); len(got) != 1 || got["ops"] != "rt-ops" {
		t.Fatalf("after the run's sign-out: %v, want only ops", got)
	}
	merged, err = MergeAzureStore(base, base, cleared)
	if err != nil {
		t.Fatal(err)
	}
	if !sealstore.Empty(merged) {
		files, _ := sealstore.Files(merged)
		t.Fatalf("signed out everywhere, yet the store holds %v", files)
	}
}

// Service principals merge by client and tenant.
func TestMergeAzureStoreServicePrincipals(t *testing.T) {
	sp := func(entries ...string) []byte {
		var list []map[string]string
		for _, e := range entries {
			id, secret, _ := strings.Cut(e, "=")
			list = append(list, map[string]string{"client_id": id, "tenant": "t", "client_secret": secret})
		}
		b, _ := json.Marshal(list)
		return b
	}
	base := store(t, map[string][]byte{"service_principal_entries.json": sp("app1=s1")})
	current := store(t, map[string][]byte{"service_principal_entries.json": sp("app1=s1", "app2=s2")})
	after := store(t, map[string][]byte{"service_principal_entries.json": sp("app1=s1-new", "app3=s3")})
	merged, err := MergeAzureStore(base, current, after)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := sealstore.Files(merged)
	var got []map[string]string
	if err := json.Unmarshal(files["service_principal_entries.json"], &got); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{}
	for _, e := range got {
		secrets[e["client_id"]] = e["client_secret"]
	}
	if len(secrets) != 3 || secrets["app1"] != "s1-new" || secrets["app2"] != "s2" || secrets["app3"] != "s3" {
		t.Fatalf("merged service principals %v", secrets)
	}
}

// A file the merge cannot read is the run's, whole: never worse than the
// reseal without a merge.
func TestMergeAzureStoreUnreadableIsTheRuns(t *testing.T) {
	base := store(t, map[string][]byte{"msal_token_cache.json": []byte("not json")})
	current := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"ops": "rt-ops"})})
	after := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-2"})})
	merged, err := MergeAzureStore(base, current, after)
	if err != nil {
		t.Fatal(err)
	}
	if got := refreshTokens(t, merged); len(got) != 1 || got["dev"] != "rt-2" {
		t.Fatalf("an unreadable base: %v, want the run's store", got)
	}
}

// Through the vault: a reseal whose read was overtaken by another run's
// merges; one that was not replaces.
func TestAzureStoreResealMergesOnlyWhenOvertaken(t *testing.T) {
	home := t.TempDir()
	v := newTestVault(t)
	dir := AzureConfigDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "msal_token_cache.json"), msal(t, map[string]string{"dev": "rt-1"}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := AzureStore.Seal(v, home)
	if err != nil || len(res.Files) != 1 {
		t.Fatalf("sealed %v, %v", res.Files, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "msal_token_cache.json")); !os.IsNotExist(err) {
		t.Fatal("the token cache is still on disk")
	}
	if _, err := os.Stat(filepath.Join(dir, "config")); err != nil {
		t.Fatalf("settings went with the store: %v", err)
	}

	// Two runs start from the same store.
	baseA, dekA, err := AzureStore.ReadSealed(v)
	if err != nil {
		t.Fatal(err)
	}
	baseB, dekB, _ := AzureStore.ReadSealed(v)
	// B signs in a second account and seals first: nothing overtook it.
	afterB := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops"})})
	if _, err := AzureStore.Reseal(v, home, "", baseB, dekB, afterB); err != nil {
		t.Fatal(err)
	}
	// A refreshed dev meanwhile.
	afterA := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-2"})})
	if _, err := AzureStore.Reseal(v, home, "", baseA, dekA, afterA); err != nil {
		t.Fatal(err)
	}
	sealed, _, _ := AzureStore.ReadSealed(v)
	if got := refreshTokens(t, sealed); got["dev"] != "rt-2" || got["ops"] != "rt-ops" {
		t.Fatalf("after both reseals: %v", got)
	}
	// Restored whole on undo.
	written, err := AzureStore.Unseal(v, home)
	if err != nil || len(written) != 1 {
		t.Fatalf("unsealed %v, %v", written, err)
	}
}

// MSAL writes its cache indented; a merged store must compare to the next
// run's file entry by entry, not as "everything changed".
func TestMergeAzureStoreIgnoresLayout(t *testing.T) {
	indent := func(b []byte) []byte {
		var out bytes.Buffer
		if err := json.Indent(&out, b, "", "    "); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	// Run A starts from a compact (merged) base and rewrites the file
	// indented, changing nothing; meanwhile run B signed ops out.
	base := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops"})})
	current := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1"})})
	after := store(t, map[string][]byte{"msal_token_cache.json": indent(msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops"}))})
	merged, err := MergeAzureStore(base, current, after)
	if err != nil {
		t.Fatal(err)
	}
	if got := refreshTokens(t, merged); len(got) != 1 || got["dev"] != "rt-1" {
		t.Fatalf("an unchanged but re-indented run undid a sign-out: %v", got)
	}
	files, _ := sealstore.Files(merged)
	if !bytes.Contains(files["msal_token_cache.json"], []byte("\n    \"")) {
		t.Fatalf("merged cache is not in MSAL's layout: %s", files["msal_token_cache.json"])
	}
}

// A refresh racing a sign-out: the run rotated ops's token while another
// run signed ops out. The sign-out stands.
func TestMergeAzureStoreSignOutBeatsARefresh(t *testing.T) {
	base := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops"})})
	current := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1"})})
	after := store(t, map[string][]byte{"msal_token_cache.json": msal(t, map[string]string{"dev": "rt-1", "ops": "rt-ops-2"})})
	merged, err := MergeAzureStore(base, current, after)
	if err != nil {
		t.Fatal(err)
	}
	if got := refreshTokens(t, merged); len(got) != 1 || got["ops"] != "" {
		t.Fatalf("a signed-out account's refresh token came back: %v", got)
	}
}

// Undo's current-copy restore writes the vault's store over the seal-day
// files, and a re-wrap with a plaintext login keeps vault-only accounts.
func TestAzureStoreRestoreCurrentAndRewrap(t *testing.T) {
	home := t.TempDir()
	v := newTestVault(t)
	dir := AzureConfigDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(accounts map[string]string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "msal_token_cache.json"), msal(t, accounts), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]string{"dev": "rt-1"})
	if _, err := AzureStore.Seal(v, home); err != nil {
		t.Fatal(err)
	}
	// A login made without the shim: the plaintext has ops only.
	write(map[string]string{"ops": "rt-ops"})
	if _, err := AzureStore.Seal(v, home); err != nil {
		t.Fatal(err)
	}
	sealed, _, _ := AzureStore.ReadSealed(v)
	if got := refreshTokens(t, sealed); got["dev"] != "rt-1" || got["ops"] != "rt-ops" {
		t.Fatalf("re-wrap lost a vault-only account: %v", got)
	}
	// Undo put back a seal-day file; the current copy goes over it.
	write(map[string]string{"dev": "rt-OLD"})
	if _, err := AzureStore.RestoreCurrent(v, home); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "msal_token_cache.json")) // #nosec G304 -- test path
	if !bytes.Contains(b, []byte("rt-1")) || bytes.Contains(b, []byte("rt-OLD")) {
		t.Fatalf("restored cache %s", b)
	}
}
