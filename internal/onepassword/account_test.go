// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSplitAndPinAccount(t *testing.T) {
	cases := []struct {
		in, bare, account string
	}{
		{"op://v/i/f", "op://v/i/f", ""},
		{"op://v/i/f?account=ACC1", "op://v/i/f", "ACC1"},
		{"op://v/i/f?attribute=otp", "op://v/i/f?attribute=otp", ""},
		{"op://v/i/f?attribute=otp&account=ACC1", "op://v/i/f?attribute=otp", "ACC1"},
		{"op://app-prod/ssh/private key?ssh-format=openssh&account=ACC1", "op://app-prod/ssh/private key?ssh-format=openssh", "ACC1"},
	}
	for _, c := range cases {
		bare, account := SplitAccount(c.in)
		if bare != c.bare || account != c.account {
			t.Errorf("SplitAccount(%q) = (%q, %q), want (%q, %q)", c.in, bare, account, c.bare, c.account)
		}
	}
	if got := PinAccount("op://v/i/f", "ACC1"); got != "op://v/i/f?account=ACC1" {
		t.Errorf("PinAccount = %q", got)
	}
	if got := PinAccount("op://v/i/f?attribute=otp", "ACC1"); got != "op://v/i/f?attribute=otp&account=ACC1" {
		t.Errorf("PinAccount with a query = %q", got)
	}
	if got := PinAccount("op://v/i/f?account=OLD", "NEW"); got != "op://v/i/f?account=NEW" {
		t.Errorf("PinAccount over an existing pin = %q", got)
	}
	if got := PinAccount("op://v/i/f", ""); got != "op://v/i/f" {
		t.Errorf("PinAccount with no account = %q, want unchanged", got)
	}
	// A pinned reference is still a valid reference shape.
	if err := ValidateRef("op://v/i/f?account=ACC1"); err != nil {
		t.Errorf("ValidateRef rejects a pinned reference: %v", err)
	}
}

func TestSelectAccountsMatchesLikeOpAccount(t *testing.T) {
	all := []Account{
		{ID: "ACC1", UserID: "USER1", URL: "https://my.1password.com", Email: "me@example.com"},
		{ID: "ACC2", UserID: "USER2", URL: "https://corp.1password.com", Shorthand: "corp"},
	}
	for want, key := range map[string]string{
		"ACC1": "my.1password.com",
		"ACC2": "corp",
		"":     "nobody.1password.com",
	} {
		got := selectAccounts(all, key)
		switch {
		case want == "" && got != nil:
			t.Errorf("selectAccounts(%q) = %v, want nil (no match → op's default)", key, got)
		case want != "" && (len(got) != 1 || got[0].ID != want):
			t.Errorf("selectAccounts(%q) = %v, want %s", key, got, want)
		}
	}
	for _, key := range []string{"https://my.1password.com", "USER2", "acc2", "ME@EXAMPLE.COM"} {
		if got := selectAccounts(all, key); len(got) != 1 {
			t.Errorf("selectAccounts(%q) = %v, want one account", key, got)
		}
	}
	if got := selectAccounts(all, ""); len(got) != 2 {
		t.Errorf("selectAccounts(\"\") = %v, want every account", got)
	}
}

const twoAccountsJSON = `[{"url":"https://my.1password.com","email":"me@example.com","user_uuid":"USER1","account_uuid":"ACC1"},` +
	`{"url":"https://corp.1password.com","email":"me@corp.example","user_uuid":"USER2","account_uuid":"ACC2","shorthand":"corp"}]`

// fakeOpAccounts builds a fake op that answers `account list` with
// accountsJSON, and `item list` / `item get -` / `read` per --account
// from the per-account bodies, failing for an account with no entry.
// Every invocation appends its full argument line to callLog.
func fakeOpAccounts(t *testing.T, accountsJSON string, perAccount map[string][2]string) (path, callLog string) {
	t.Helper()
	callLog = t.TempDir() + "/calls"
	script := `echo "$*" >> ` + callLog + `
ACC=""
if [ "$1" = "--account" ]; then ACC="$2"; shift 2; fi
case "$1 $2" in
"account list")
cat <<'JSONEOF'
` + accountsJSON + `
JSONEOF
exit 0 ;;
"read -n")
case "$ACC" in
`
	for id := range perAccount {
		script += id + `) printf 'value-in-` + id + `'; exit 0 ;;
`
	}
	script += `*) echo "[ERROR] isn't a vault in this account" >&2; exit 1 ;;
esac ;;
esac
case "$ACC" in
`
	for id, bodies := range perAccount {
		script += id + `)
case "$1 $2" in
"item list") cat <<'JSONEOF'
` + bodies[0] + `
JSONEOF
;;
"item get") cat >/dev/null; cat <<'JSONEOF'
` + bodies[1] + `
JSONEOF
;;
esac ;;
`
	}
	script += `*) echo "[ERROR] account $ACC is not signed in" >&2; exit 1 ;;
esac
`
	return fakeOp(t, script), callLog
}

func TestInventoryCoversEveryAccountAndPinsEachLink(t *testing.T) {
	bin, calls := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{
		"ACC1": {`[{"id":"p1","category":"LOGIN"}]`, fmt.Sprintf(inventoryItemTemplate, "p1", "personal")},
		"ACC2": {`[{"id":"c1","category":"LOGIN"},{"id":"c2","category":"CREDIT_CARD"}]`, fmt.Sprintf(inventoryItemTemplate, "c1", "corp")},
	})
	t.Setenv("OP_ACCOUNT", "")
	var ticks []string
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(func(read, listed int) {
		ticks = append(ticks, fmt.Sprintf("%d/%d", read, listed))
	})
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if ix.Listed() != 2 || ix.Items() != 2 || ix.Incomplete() != "" {
		t.Errorf("Listed/Items/Incomplete = %d/%d/%q, want 2/2 (the card filtered) and complete", ix.Listed(), ix.Items(), ix.Incomplete())
	}
	e, ok := ix.RefFor([]byte("value-of-personal"))
	if !ok || e.IDRef != "op://v/p1/f?account=ACC1" {
		t.Errorf("personal link = (%q, %v), want pinned to ACC1", e.IDRef, ok)
	}
	e, ok = ix.RefFor([]byte("value-of-corp"))
	if !ok || e.IDRef != "op://v/c1/f?account=ACC2" {
		t.Errorf("corp link = (%q, %v), want pinned to ACC2", e.IDRef, ok)
	}
	if got := strings.Join(ticks, " "); got != "0/2 1/2 2/2" {
		t.Errorf("progress = %q, want cumulative across accounts", got)
	}
	log, _ := os.ReadFile(calls) // #nosec G304 -- test temp file
	for _, want := range []string{"--account ACC1 item list", "--account ACC2 item list", "--account ACC1 item get -", "--account ACC2 item get -"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("op was never invoked as %q:\n%s", want, log)
		}
	}
}

func TestInventoryHonorsOPAccount(t *testing.T) {
	bin, calls := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{
		"ACC1": {`[{"id":"p1","category":"LOGIN"}]`, fmt.Sprintf(inventoryItemTemplate, "p1", "personal")},
		"ACC2": {`[{"id":"c1","category":"LOGIN"}]`, fmt.Sprintf(inventoryItemTemplate, "c1", "corp")},
	})
	t.Setenv("OP_ACCOUNT", "my.1password.com")
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if ix.Listed() != 1 {
		t.Errorf("Listed() = %d, want the one account OP_ACCOUNT names", ix.Listed())
	}
	if _, ok := ix.RefFor([]byte("value-of-corp")); ok {
		t.Error("the account OP_ACCOUNT excluded was enumerated")
	}
	if log, _ := os.ReadFile(calls); strings.Contains(string(log), "--account ACC2") { // #nosec G304 -- test temp file
		t.Errorf("op was invoked for the excluded account:\n%s", log)
	}
}

func TestInventoryOneFailingAccountIsAShortfallNotAFailure(t *testing.T) {
	// ACC2 is listed but has no fake body: every call for it fails.
	bin, _ := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{
		"ACC1": {`[{"id":"p1","category":"LOGIN"}]`, fmt.Sprintf(inventoryItemTemplate, "p1", "personal")},
	})
	t.Setenv("OP_ACCOUNT", "")
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if _, ok := ix.RefFor([]byte("value-of-personal")); !ok {
		t.Error("the working account was not indexed")
	}
	if !strings.Contains(ix.Incomplete(), "corp.1password.com") || !strings.Contains(ix.Incomplete(), "not signed in") {
		t.Errorf("Incomplete() = %q, want the failing account named with op's line", ix.Incomplete())
	}
}

func TestInventoryEveryAccountFailingIsAnError(t *testing.T) {
	bin, _ := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{})
	t.Setenv("OP_ACCOUNT", "")
	if _, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil); err == nil {
		t.Fatal("Inventory succeeded with every account failing")
	}
}

func TestResolveRefPassesThePinAsAccount(t *testing.T) {
	bin, calls := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{"ACC2": {}})
	r := &Resolver{path: bin, verify: noVerify}
	got, err := r.ResolveRef("op://v/i/f?account=ACC2")
	if err != nil || string(got) != "value-in-ACC2" {
		t.Fatalf("ResolveRef = (%q, %v), want the pinned account's value", got, err)
	}
	log, _ := os.ReadFile(calls) // #nosec G304 -- test temp file
	if !strings.Contains(string(log), "--account ACC2 read -n op://v/i/f\n") {
		t.Errorf("op read was not invoked with --account and the bare reference:\n%s", log)
	}
	// Unpinned on a two-account machine: the failure names the likely cause.
	_, err = r.ResolveRef("op://v/i/f")
	if err == nil || !strings.Contains(err.Error(), "signed in to 2 accounts") {
		t.Errorf("unpinned failure = %v, want the multi-account hint", err)
	}
}

func TestPinFindsTheAccountAReferenceResolvesIn(t *testing.T) {
	bin, _ := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{"ACC2": {}})
	r := &Resolver{path: bin, verify: noVerify}
	pinned, err := r.Pin("op://v/i/f")
	if err != nil || pinned != "op://v/i/f?account=ACC2" {
		t.Errorf("Pin = (%q, %v), want the second account, the one it resolves in", pinned, err)
	}
	// Already pinned: kept as is.
	if pinned, err := r.Pin("op://v/i/f?account=ACC2"); err != nil || pinned != "op://v/i/f?account=ACC2" {
		t.Errorf("Pin of a pinned ref = (%q, %v)", pinned, err)
	}
	// Resolves nowhere: the error says every account was tried.
	bin2, _ := fakeOpAccounts(t, twoAccountsJSON, map[string][2]string{})
	if _, err := (&Resolver{path: bin2, verify: noVerify}).Pin("op://v/i/f"); err == nil || !strings.Contains(err.Error(), "tried all 2") {
		t.Errorf("Pin with no resolving account = %v, want the tried-all error", err)
	}
}

func TestPinWithOneAccountPinsIt(t *testing.T) {
	one := `[{"url":"https://my.1password.com","user_uuid":"USER1","account_uuid":"ACC1"}]`
	bin, _ := fakeOpAccounts(t, one, map[string][2]string{"ACC1": {}})
	pinned, err := (&Resolver{path: bin, verify: noVerify}).Pin("op://v/i/f")
	if err != nil || pinned != "op://v/i/f?account=ACC1" {
		t.Errorf("Pin = (%q, %v), want pinned to the only account", pinned, err)
	}
}
