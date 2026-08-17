// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOpInventory builds a fake op that answers `item list` with listJSON
// and `item get -` with getJSON, failing loudly on anything else. When
// getJSON is empty, an `item get` invocation drops a marker file so the
// test can assert it never ran.
func fakeOpInventory(t *testing.T, listJSON, getJSON string) (path, getMarker string) {
	t.Helper()
	dir := t.TempDir()
	getMarker = filepath.Join(dir, "get-ran")
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
		script += `cat >/dev/null
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
	return fakeOp(t, script), getMarker
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
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory()
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
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory()
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
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory()
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if _, ok := ix.RefFor([]byte("ghp_abcdefgh")); !ok {
		t.Error("array-shaped item get output not indexed")
	}
}

func TestInventoryEmptyVaultSkipsItemGet(t *testing.T) {
	bin, marker := fakeOpInventory(t, `[]`, "")
	ix, err := (&Resolver{path: bin, verify: noVerify}).Inventory()
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
	_, err := (&Resolver{path: bin, verify: noVerify}).Inventory()
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
	_, err := (&Resolver{path: bin, verify: failVerify}).Inventory()
	if err == nil || !strings.Contains(err.Error(), "signature rejected") {
		t.Fatalf("err = %v, want the verification failure", err)
	}
	if _, statErr := os.Stat(bin + ".ran"); statErr == nil {
		t.Error("unverified binary was executed")
	}
}
