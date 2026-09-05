// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOpInventory builds a fake op that answers `item list` with listJSON
// and `item get -` with getJSON, failing loudly on anything else. What
// `item get -` received on stdin is written to getStdin, so a test can
// assert which items were asked for. When getJSON is empty, an `item get`
// invocation drops a marker file instead so the test can assert it never
// ran.
func fakeOpInventory(t *testing.T, listJSON, getJSON string) (path, getMarker string) {
	path, getMarker, _ = fakeOpInventoryStdin(t, listJSON, getJSON)
	return path, getMarker
}

func fakeOpInventoryStdin(t *testing.T, listJSON, getJSON string) (path, getMarker, getStdin string) {
	t.Helper()
	dir := t.TempDir()
	getMarker = filepath.Join(dir, "get-ran")
	getStdin = filepath.Join(dir, "get-stdin")
	script := `
case "$1 $2" in
"item list")
cat <<'JSONEOF'
` + listJSON + `
JSONEOF
;;
"item get")
`
	if getJSON == "" {
		script += `touch ` + getMarker + `
echo "item get must not run" >&2
exit 3
`
	} else {
		script += `cat >` + getStdin + `
cat <<'JSONEOF'
` + getJSON + `
JSONEOF
`
	}
	script += `;;
*)
echo "unexpected arguments: $*" >&2
exit 2
;;
esac
`
	return fakeOp(t, script), getMarker, getStdin
}

const inventoryListTwo = `[{"id":"item-b"},{"id":"item-a"}]`

// Two items, streamed as concatenated objects (op's multi-item shape).
// Covers: a STRING field (never indexed), a CONCEALED field under the
// 8-byte floor, a CONCEALED field missing its reference key (NameRef
// falls back to names), and a field with no id (skipped entirely).
const inventoryGetStream = `{
  "id": "item-b",
  "title": "Stripe",
  "vault": {"id": "vault-1", "name": "Personal"},
  "fields": [
    {"id": "f1", "type": "CONCEALED", "label": "credential", "value": "sk_live_1234567890", "reference": "op://Personal/Stripe/credential"},
    {"id": "f2", "type": "STRING", "label": "username", "value": "not-a-secret-but-long"},
    {"id": "f3", "type": "CONCEALED", "label": "pin", "value": "admin"}
  ]
}
{
  "id": "item-a",
  "title": "Postgres",
  "vault": {"id": "vault-1", "name": "Personal"},
  "fields": [
    {"id": "f1", "type": "CONCEALED", "label": "password", "value": "correct-horse-battery"},
    {"id": "", "type": "CONCEALED", "label": "orphan", "value": "no-id-no-reference-possible"}
  ]
}`

func TestInventoryIndexesConcealedFieldsOnly(t *testing.T) {
	bin, _ := fakeOpInventory(t, inventoryListTwo, inventoryGetStream)
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if ix.Items() != 2 {
		t.Errorf("Items() = %d, want 2", ix.Items())
	}

	e, ok := ix.RefFor([]byte("sk_live_1234567890"))
	if !ok {
		t.Fatal("concealed value not indexed")
	}
	if e.IDRef != "op://vault-1/item-b/f1" {
		t.Errorf("IDRef = %q, want the id-form reference", e.IDRef)
	}
	if e.NameRef != "op://Personal/Stripe/credential" {
		t.Errorf("NameRef = %q, want op's own reference key", e.NameRef)
	}

	if e, ok := ix.RefFor([]byte("correct-horse-battery")); !ok {
		t.Error("second item's concealed value not indexed")
	} else if e.NameRef != "op://Personal/Postgres/password" {
		t.Errorf("NameRef fallback = %q, want name-built reference", e.NameRef)
	}

	if _, ok := ix.RefFor([]byte("not-a-secret-but-long")); ok {
		t.Error("STRING-typed field was indexed; only CONCEALED must be")
	}
	if _, ok := ix.RefFor([]byte("admin")); ok {
		t.Error("value under the length floor was indexed")
	}
	if _, ok := ix.RefFor([]byte("no-id-no-reference-possible")); ok {
		t.Error("field with no id was indexed; no rename-proof reference exists for it")
	}
}

func TestInventoryFirstWinsIsDeterministic(t *testing.T) {
	// The same value in two items; item ids arrive in reverse order, and
	// the index must still pick the lower (vault id, item id) every run.
	get := `{
  "id": "item-z",
  "title": "Copy",
  "vault": {"id": "vault-1", "name": "Personal"},
  "fields": [{"id": "f1", "type": "CONCEALED", "label": "token", "value": "shared-value-12345"}]
}
{
  "id": "item-a",
  "title": "Original",
  "vault": {"id": "vault-1", "name": "Personal"},
  "fields": [{"id": "f1", "type": "CONCEALED", "label": "token", "value": "shared-value-12345"}]
}`
	bin, _ := fakeOpInventory(t, `[{"id":"item-z"},{"id":"item-a"}]`, get)
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	e, ok := ix.RefFor([]byte("shared-value-12345"))
	if !ok {
		t.Fatal("shared value not indexed")
	}
	if e.IDRef != "op://vault-1/item-a/f1" {
		t.Errorf("IDRef = %q, want the deterministic first item (item-a)", e.IDRef)
	}
}

func TestInventoryAcceptsArrayOutput(t *testing.T) {
	get := `[{
  "id": "item-a",
  "title": "GitHub",
  "vault": {"id": "vault-1", "name": "Personal"},
  "fields": [{"id": "f1", "type": "CONCEALED", "label": "token", "value": "ghp_abcdefgh"}]
}]`
	bin, _ := fakeOpInventory(t, `[{"id":"item-a"}]`, get)
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if _, ok := ix.RefFor([]byte("ghp_abcdefgh")); !ok {
		t.Error("array-shaped item get output not indexed")
	}
}

func TestInventoryEmptyVaultSkipsItemGet(t *testing.T) {
	bin, marker := fakeOpInventory(t, `[]`, "")
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory on empty vault: %v", err)
	}
	if ix.Items() != 0 {
		t.Errorf("Items() = %d, want 0", ix.Items())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("op item get ran for an empty item list")
	}
}

func TestInventorySurfacesSignedOutError(t *testing.T) {
	bin := fakeOp(t, `
echo '[ERROR] 2026/08/17 account is not signed in' >&2
exit 1
`)
	_, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err == nil {
		t.Fatal("Inventory succeeded against a signed-out op")
	}
	if !strings.Contains(err.Error(), "not signed in") {
		t.Errorf("error %q does not carry op's own stderr line", err)
	}
}

func TestInventoryVerifyFailureIsClosedBeforeExec(t *testing.T) {
	bin := fakeOp(t, `touch "$0.ran"; exit 0`)
	failVerify := func(string) error { return errors.New("signature rejected") }
	_, err := (&Resolver{path: bin, verify: failVerify}).Inventory(nil)
	if err == nil || !strings.Contains(err.Error(), "signature rejected") {
		t.Fatalf("err = %v, want the verification failure", err)
	}
	if _, statErr := os.Stat(bin + ".ran"); statErr == nil {
		t.Error("unverified binary was executed")
	}
}

func TestInventorySkipsPIICategoriesBeforeFetching(t *testing.T) {
	list := `[{"id":"card","category":"CREDIT_CARD"},{"id":"login","category":"LOGIN"},` +
		`{"id":"bank","category":"BANK_ACCOUNT"},{"id":"nocat"},{"id":"api","category":"API_CREDENTIAL"}]`
	get := `{"id":"login","title":"L","vault":{"id":"v","name":"P"},"fields":[{"id":"f","type":"CONCEALED","label":"password","value":"long-enough-value"}]}`
	bin, _, stdin := fakeOpInventoryStdin(t, list, get)
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	got, err := os.ReadFile(stdin) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("item get received no stdin: %v", err)
	}
	for _, id := range []string{"card", "bank"} {
		if strings.Contains(string(got), `"`+id+`"`) {
			t.Errorf("PII item %q was handed to op item get:\n%s", id, got)
		}
	}
	for _, id := range []string{"login", "nocat", "api"} {
		if !strings.Contains(string(got), `"`+id+`"`) {
			t.Errorf("credential item %q was filtered out:\n%s", id, got)
		}
	}
	if ix.Listed() != 3 {
		t.Errorf("Listed() = %d, want 3 (the kept items)", ix.Listed())
	}
}

func TestInventoryAllPIIAccountSkipsItemGet(t *testing.T) {
	bin, marker := fakeOpInventory(t, `[{"id":"card","category":"CREDIT_CARD"}]`, "")
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if ix.Listed() != 0 || ix.Items() != 0 {
		t.Errorf("Listed/Items = %d/%d, want 0/0", ix.Listed(), ix.Items())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("op item get ran for a worklist the filter emptied")
	}
}

func TestInventoryReportsProgressPerItem(t *testing.T) {
	bin, _ := fakeOpInventory(t, inventoryListTwo, inventoryGetStream)
	var seen []string
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(func(read, listed int) {
		seen = append(seen, fmt.Sprintf("%d/%d", read, listed))
	})
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	want := "0/2 1/2 2/2"
	if got := strings.Join(seen, " "); got != want {
		t.Errorf("progress = %q, want %q", got, want)
	}
	if ix.Items() != 2 || ix.Listed() != 2 || ix.Incomplete() != "" {
		t.Errorf("Items/Listed/Incomplete = %d/%d/%q, want 2/2/\"\"", ix.Items(), ix.Listed(), ix.Incomplete())
	}
}

const inventoryItemTemplate = `{"id":"%s","title":"T","vault":{"id":"v","name":"P"},"fields":[{"id":"f","type":"CONCEALED","label":"password","value":"value-of-%s"}]}`

// A stream that keeps delivering must never trip the bound, however long
// it runs in total: four items 400ms apart under a 1s idle watchdog
// (1.6s total) all arrive.
func TestInventoryIdleWatchdogIsPerItemNotTotal(t *testing.T) {
	get := ""
	for _, id := range []string{"a", "b", "c", "d"} {
		get += fmt.Sprintf(inventoryItemTemplate, id, id) + "\n"
	}
	bin := fakeOp(t, `
case "$1 $2" in
"item list") echo '[{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"}]' ;;
"item get")
cat >/dev/null
while IFS= read -r line; do printf '%s\n' "$line"; sleep 0.4; done <<'JSONEOF'
`+get+`JSONEOF
;;
esac
`)
	ix, err := (&Resolver{path: bin, verify: noVerify, timeout: time.Second}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if ix.Items() != 4 || ix.Incomplete() != "" {
		t.Errorf("Items/Incomplete = %d/%q, want 4 read with nothing incomplete", ix.Items(), ix.Incomplete())
	}
}

// One item, then silence: the watchdog kills op, the item that arrived
// stays indexed, and the shortfall is on the index — not an error.
func TestInventoryStallKeepsPartialIndex(t *testing.T) {
	bin := fakeOp(t, `
case "$1 $2" in
"item list") echo '[{"id":"a"},{"id":"b"}]' ;;
"item get")
cat >/dev/null
echo '`+fmt.Sprintf(inventoryItemTemplate, "a", "a")+`'
sleep 30
;;
esac
`)
	start := time.Now()
	ix, err := (&Resolver{path: bin, verify: noVerify, timeout: time.Second}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Inventory took %s; the watchdog did not bound the stall", elapsed)
	}
	if _, ok := ix.RefFor([]byte("value-of-a")); !ok {
		t.Error("the item that arrived before the stall was not indexed")
	}
	if ix.Items() != 1 || ix.Listed() != 2 {
		t.Errorf("Items/Listed = %d/%d, want 1/2", ix.Items(), ix.Listed())
	}
	if !strings.Contains(ix.Incomplete(), "stalled") {
		t.Errorf("Incomplete() = %q, want the stall named", ix.Incomplete())
	}
}

// op answering some items then exiting non-zero (a rate limit, a vault
// gone mid-run): partial index, op's own line as the shortfall.
func TestInventoryEarlyExitKeepsPartialIndex(t *testing.T) {
	bin := fakeOp(t, `
case "$1 $2" in
"item list") echo '[{"id":"a"},{"id":"b"}]' ;;
"item get")
cat >/dev/null
echo '`+fmt.Sprintf(inventoryItemTemplate, "a", "a")+`'
echo '[ERROR] 2026/09/05 rate limit exceeded' >&2
exit 1
;;
esac
`)
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if ix.Items() != 1 || !strings.Contains(ix.Incomplete(), "rate limit exceeded") {
		t.Errorf("Items/Incomplete = %d/%q, want 1 read and op's own error line", ix.Items(), ix.Incomplete())
	}
}

// Nothing read at all before op fails is a failed enumeration, as before.
func TestInventoryNoItemsThenFailureIsAnError(t *testing.T) {
	bin := fakeOp(t, `
case "$1 $2" in
"item list") echo '[{"id":"a"}]' ;;
"item get") cat >/dev/null; echo '[ERROR] vault not found' >&2; exit 1 ;;
esac
`)
	_, err := (&Resolver{path: bin, verify: noVerify}).Inventory(nil)
	if err == nil || !strings.Contains(err.Error(), "vault not found") {
		t.Fatalf("err = %v, want op's own error", err)
	}
}
