// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"time"
)

// minLinkableValueLen is the floor under which a 1Password field value is
// never indexed for matching: a `PASSWORD=admin` line must not silently
// link to whichever item also says "admin". Byte-exact matching plus this
// floor is the whole anti-collision story — no fuzz, no normalization.
const minLinkableValueLen = 8

// Index maps the SHA-256 of each concealed 1Password field value to the
// reference naming that field. It holds hashes, never the values: the
// enumeration's plaintext lives only inside Inventory's call frame, and
// what migrate keeps around for the duration of a run is unlinkable
// digests plus op:// strings.
type Index struct {
	byHash map[[sha256.Size]byte]IndexEntry
	items  int
}

// IndexEntry is one linkable 1Password field. IDRef is the rename-proof
// form built from the item JSON's own vault/item/field ids — what gets
// stored. NameRef is the human-readable form for display; it may contain
// spaces or other characters outside the reference charset, which is fine
// on screen and exactly why it is not the stored one.
type IndexEntry struct {
	IDRef   string
	NameRef string
}

// RefFor returns the entry for a value, matching byte-exact via hash.
func (ix *Index) RefFor(value []byte) (IndexEntry, bool) {
	if ix == nil || len(value) < minLinkableValueLen {
		return IndexEntry{}, false
	}
	e, ok := ix.byHash[sha256.Sum256(value)]
	return e, ok
}

// Items reports how many 1Password items the enumeration covered — the
// honest "checked N items" number for the mutation log.
func (ix *Index) Items() int {
	if ix == nil {
		return 0
	}
	return ix.items
}

// opItem is the slice of `op item get --format json` output this package
// reads. Fields it doesn't name are ignored on purpose: op's schema is
// theirs to evolve, and everything here degrades to "field not indexed".
type opItem struct {
	ID    string `json:"id"`
	Vault struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	Title  string `json:"title"`
	Fields []struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Label     string `json:"label"`
		Value     string `json:"value"`
		Reference string `json:"reference"`
	} `json:"fields"`
}

// Inventory enumerates every item the signed-in account can read and
// returns an Index of its concealed field values, for migrate's
// link-instead-of-copy dedupe (design/1password-adapter.md). One
// authenticated enumeration — `op item list` piped into `op item get -`,
// the CLI's own documented bulk pattern — so the user answers at most one
// 1Password authorization prompt per run. Only fields op marks CONCEALED
// are indexed: that is 1Password's own "this is a secret" bit, and it
// naturally excludes usernames, URLs, and Secure Note bodies.
//
// The raw JSON (which carries the values) is wiped before returning;
// Go strings parsed out of it are unwipable, so this is best-effort
// hygiene on the same terms as migrate's own file parsing, not a
// guarantee.
func (r *Resolver) Inventory() (*Index, error) {
	bin, err := r.bin()
	if err != nil {
		return nil, err
	}

	timeout := r.timeout
	if timeout <= 0 {
		timeout = resolveTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	list, err := runOp(ctx, bin, nil, "item", "list", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("op item list failed: %w", err)
	}
	defer wipeBytes(list)

	// An account with zero items lists `[]`; don't hand `op item get -`
	// an empty worklist to choke on.
	var listed []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(list), &listed); err != nil {
		return nil, fmt.Errorf("op item list output not understood: %v", err)
	}
	if len(listed) == 0 {
		return &Index{byHash: map[[sha256.Size]byte]IndexEntry{}}, nil
	}

	raw, err := runOp(ctx, bin, list, "item", "get", "-", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("op item get failed: %w", err)
	}
	defer wipeBytes(raw)

	items, err := parseItems(raw)
	if err != nil {
		return nil, err
	}

	// Deterministic first-wins for a value present in several fields: the
	// choice is cosmetic (same value, same secret), but it must not change
	// between runs of the same vault state.
	sort.Slice(items, func(i, j int) bool {
		if items[i].Vault.ID != items[j].Vault.ID {
			return items[i].Vault.ID < items[j].Vault.ID
		}
		return items[i].ID < items[j].ID
	})

	ix := &Index{byHash: map[[sha256.Size]byte]IndexEntry{}, items: len(items)}
	for _, it := range items {
		for _, f := range it.Fields {
			if f.Type != "CONCEALED" || len(f.Value) < minLinkableValueLen {
				continue
			}
			if it.Vault.ID == "" || it.ID == "" || f.ID == "" {
				continue // no rename-proof reference to build; skip rather than store a fragile one
			}
			sum := sha256.Sum256([]byte(f.Value))
			if _, taken := ix.byHash[sum]; taken {
				continue
			}
			name := f.Reference
			if name == "" {
				name = fmt.Sprintf("op://%s/%s/%s", it.Vault.Name, it.Title, f.Label)
			}
			ix.byHash[sum] = IndexEntry{
				IDRef:   fmt.Sprintf("op://%s/%s/%s", it.Vault.ID, it.ID, f.ID),
				NameRef: name,
			}
		}
	}
	return ix, nil
}

// parseItems accepts both shapes `op item get - --format json` emits: a
// JSON array, or a concatenated stream of objects (one per piped item).
func parseItems(raw []byte) ([]opItem, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var items []opItem
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("op item get output not understood: %v", err)
		}
		return items, nil
	}
	var items []opItem
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for dec.More() {
		var it opItem
		if err := dec.Decode(&it); err != nil {
			return nil, fmt.Errorf("op item get output not understood: %v", err)
		}
		items = append(items, it)
	}
	return items, nil
}

// runOp executes one op invocation under ctx with stdin (nil for none),
// returning stdout. Errors surface op's own first stderr line — the
// message a signed-out or locked CLI prints is the actionable one.
func runOp(ctx context.Context, bin string, stdin []byte, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is signature-verified by the caller's bin(); args are fixed literals
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Same reasoning as ResolveRef: without WaitDelay, a helper op leaves
	// behind holds the pipes open past the kill and the bound stops
	// bounding.
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		wipeBytes(stdout.Bytes())
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timed out (waiting for a 1Password unlock that never came?)")
		}
		if detail := firstLine(stderr.String()); detail != "" {
			return nil, fmt.Errorf("%s", detail)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// wipeBytes zeroes b — best-effort plaintext hygiene for buffers that
// carried field values.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
