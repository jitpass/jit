// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// MinLinkableValueLen is the floor under which a 1Password field value is
// never indexed for matching: a `PASSWORD=admin` line must not silently
// link to whichever item also says "admin". Byte-exact matching plus this
// floor is the whole anti-collision story — no fuzz, no normalization.
// Exported so migrate can tell a linkable candidate from a value that
// could never match, and skip the enumeration for a run that has none.
const MinLinkableValueLen = 8

// skipCategories are the 1Password item categories the enumeration never
// fetches. None of them holds a developer credential; what they do hold
// behind CONCEALED fields is a card's CVV and PIN, a bank account's phone
// PIN, and identity-document details — bytes that must not pass through
// jit's memory to be hashed, and fetches that in a Business account each
// land an "item accessed" event in the activity log for nothing. A
// deny-list, not an allow-list, so a category 1Password adds tomorrow is
// enumerated until someone decides otherwise. Values are the `category`
// key `op item list --format json` carries (op's own template names in
// upper snake case).
var skipCategories = map[string]bool{
	"BANK_ACCOUNT":           true,
	"CREDIT_CARD":            true,
	"DRIVER_LICENSE":         true,
	"IDENTITY":               true,
	"MEDICAL_RECORD":         true,
	"MEMBERSHIP":             true,
	"OUTDOOR_LICENSE":        true,
	"PASSPORT":               true,
	"REWARD_PROGRAM":         true,
	"SOCIAL_SECURITY_NUMBER": true,
}

// Index maps the SHA-256 of each concealed 1Password field value to the
// reference naming that field. It holds hashes, never the values: each
// item's plaintext lives only as long as its decode, and what migrate
// keeps around for the duration of a run is unlinkable digests plus
// op:// strings.
type Index struct {
	byHash map[[sha256.Size]byte]indexed
	// listed is how many items survived the category filter — what
	// `op item get -` was asked for; read is how many it answered with.
	listed, read int
	// incomplete carries op's own first stderr line when it stopped
	// answering before every listed item arrived (a rate limit, a vault
	// that went away mid-run). The items that did arrive are indexed —
	// a partial index links what it can — and the caller reports the
	// shortfall rather than hiding it.
	incomplete string
}

// indexed is an IndexEntry plus the (vault id, item id) it came from, so
// a value present in several fields settles on the same one every run.
type indexed struct {
	IndexEntry
	vaultID, itemID string
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
	if ix == nil || len(value) < MinLinkableValueLen {
		return IndexEntry{}, false
	}
	e, ok := ix.byHash[sha256.Sum256(value)]
	return e.IndexEntry, ok
}

// Items reports how many 1Password items the enumeration actually read —
// the honest "checked N items" number for the mutation log.
func (ix *Index) Items() int {
	if ix == nil {
		return 0
	}
	return ix.read
}

// Listed reports how many items the enumeration asked op for after the
// category filter. Equal to Items unless op stopped early.
func (ix *Index) Listed() int {
	if ix == nil {
		return 0
	}
	return ix.listed
}

// Incomplete is op's own error line when the enumeration ended before
// every listed item was read, or "" when it read them all.
func (ix *Index) Incomplete() string {
	if ix == nil {
		return ""
	}
	return ix.incomplete
}

// opListed is the slice of one `op item list --format json` object this
// package reads: the category, to filter on, and nothing else — the
// object itself is handed back to `op item get -` verbatim.
type opListed struct {
	Category string `json:"category"`
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

// Inventory enumerates the credential-bearing items the signed-in
// accounts can read and returns an Index of their concealed field values,
// for migrate's link-instead-of-copy dedupe (design/1password-adapter.md).
// Per account, one authenticated enumeration — `op item list` piped into
// `op item get -`, the CLI's own documented bulk pattern — so the user
// answers at most one 1Password authorization prompt per account per
// run. Every signed-in account is covered unless OP_ACCOUNT names one
// (enumerationAccounts), and each indexed reference is pinned to the
// account it came from (account.go), so the link resolves there whatever
// op's default account is later. Only fields op marks CONCEALED are
// indexed: that is 1Password's own "this is a secret" bit, and it
// naturally excludes usernames, URLs, and Secure Note bodies. (SSH Key
// items never match either: their private key is type SSHKEY, not
// CONCEALED, and on-disk key bytes rarely equal op's rendering anyway.)
//
// The item stream is decoded one object at a time as op emits it, so at
// most one item's plaintext is resident, and progress (when non-nil) is
// told after each — (read, listed), cumulative across accounts — so a
// long enumeration can show a counter instead of looking hung. The two
// op calls carry different bounds: the list waits on 1Password's unlock
// dialog, the same class of wait as jit's own Touch ID, and gets the
// resolve timeout; the get is bounded per item — an idle watchdog that
// trips when no item has arrived for that long, so a large account is
// never cut off for merely being large while a hung op is still killed.
// With several accounts, one that fails (not authorized, gone) is
// reported on the index and the others still count; only every account
// failing is a failed enumeration.
func (r *Resolver) Inventory(progress func(read, listed int)) (*Index, error) {
	bin, err := r.bin()
	if err != nil {
		return nil, err
	}

	timeout := r.timeout
	if timeout <= 0 {
		timeout = resolveTimeout
	}

	// One pass per account; a nil account set is one unpinned pass under
	// op's own default (no accounts listed, or OP_ACCOUNT matched none).
	passes := []Account{{}}
	if accounts := r.enumerationAccounts(); len(accounts) > 0 {
		passes = accounts
	}

	type pass struct {
		account  Account
		worklist []byte
		listed   int
	}
	var work []pass
	var shortfalls []string
	var firstErr error
	for _, a := range passes {
		listCtx, cancelList := context.WithTimeout(context.Background(), timeout)
		list, err := runOp(listCtx, bin, nil, accountArgs(a, "item", "list", "--format", "json")...)
		cancelList()
		if err != nil {
			err = fmt.Errorf("op item list failed: %w", err)
			if len(passes) == 1 {
				return nil, err
			}
			shortfalls = append(shortfalls, accountLabel(a)+": "+err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		worklist, listed, err := filterListed(list)
		if err != nil {
			if len(passes) == 1 {
				return nil, err
			}
			shortfalls = append(shortfalls, accountLabel(a)+": "+err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		work = append(work, pass{account: a, worklist: worklist, listed: listed})
	}
	if len(work) == 0 && firstErr != nil {
		return nil, firstErr
	}

	ix := &Index{byHash: map[[sha256.Size]byte]indexed{}}
	for _, p := range work {
		ix.listed += p.listed
	}
	// An account with zero (kept) items: don't hand `op item get -` an
	// empty worklist to choke on.
	if ix.listed == 0 {
		ix.incomplete = strings.Join(shortfalls, "; ")
		return ix, nil
	}
	if progress != nil {
		progress(0, ix.listed)
	}

	streamed := 0
	for _, p := range work {
		if p.listed == 0 {
			continue
		}
		if err := r.streamItems(bin, p.account, p.worklist, timeout, ix, progress); err != nil {
			if len(work) == 1 {
				return nil, err
			}
			shortfalls = append(shortfalls, accountLabel(p.account)+": "+err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		streamed++
	}
	if streamed == 0 && firstErr != nil {
		return nil, firstErr
	}
	// Whole-account shortfalls first, then what the streams recorded.
	if len(shortfalls) > 0 {
		if ix.incomplete != "" {
			shortfalls = append(shortfalls, ix.incomplete)
		}
		ix.incomplete = strings.Join(shortfalls, "; ")
	}
	return ix, nil
}

// accountArgs prefixes op arguments with --account for a real account and
// leaves them alone for the zero Account (op's own default).
func accountArgs(a Account, args ...string) []string {
	if a.ID == "" {
		return args
	}
	return append([]string{"--account", a.ID}, args...)
}

// accountLabel names an account in a shortfall note the way the user
// knows it — the sign-in address — never by uuid alone.
func accountLabel(a Account) string {
	switch {
	case a.URL != "":
		return a.URL
	case a.Shorthand != "":
		return a.Shorthand
	case a.ID != "":
		return a.ID
	}
	return "default account"
}

// filterListed parses `op item list` output, drops skipCategories, and
// returns the kept objects re-encoded as the JSON array `op item get -`
// accepts (each object verbatim, so op keeps the vault it already knows
// the item lives in), plus how many were kept. An object with no
// category key is kept: the filter only ever removes what it can name.
func filterListed(list []byte) ([]byte, int, error) {
	var listed []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(list), &listed); err != nil {
		return nil, 0, fmt.Errorf("op item list output not understood: %v", err)
	}
	kept := make([]json.RawMessage, 0, len(listed))
	for _, raw := range listed {
		var l opListed
		if err := json.Unmarshal(raw, &l); err == nil && skipCategories[l.Category] {
			continue
		}
		kept = append(kept, raw)
	}
	if len(kept) == 0 {
		return nil, 0, nil
	}
	worklist, err := json.Marshal(kept)
	if err != nil {
		return nil, 0, fmt.Errorf("op item list output not understood: %v", err)
	}
	return worklist, len(kept), nil
}

// streamItems runs `op item get -` over worklist and indexes each item as
// it arrives. The idle watchdog restarts on every decoded item; when it
// trips, or op exits non-zero, whatever was read stays indexed and the
// shortfall is recorded on ix — unless nothing at all was read, which is
// a failed enumeration and returns the error.
func (r *Resolver) streamItems(bin string, account Account, worklist []byte, idle time.Duration, ix *Index, progress func(read, listed int)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stalled atomic.Bool
	watchdog := time.AfterFunc(idle, func() { stalled.Store(true); cancel() })
	defer watchdog.Stop()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, accountArgs(account, "item", "get", "-", "--format", "json")...) // #nosec G204 -- bin is signature-verified by bin(); args are fixed literals plus op's own account id
	cmd.Stdin = bytes.NewReader(worklist)
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("op item get failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("op item get failed: %v", err)
	}

	read := 0
	decodeErr := decodeItems(stdout, func(it opItem) {
		watchdog.Reset(idle)
		read++
		ix.add(it, account.ID)
		if progress != nil {
			progress(ix.read, ix.listed)
		}
	})
	// Drain so op never blocks on a full pipe after a decode error, then
	// let Wait collect the exit status (and, past WaitDelay, the pipe).
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()

	if waitErr == nil && decodeErr == nil {
		return nil
	}
	var detail string
	switch {
	case stalled.Load():
		detail = fmt.Sprintf("stalled: no item arrived for %s (waiting for a 1Password unlock that never came?)", idle)
	case decodeErr != nil && waitErr == nil:
		detail = fmt.Sprintf("op item get output not understood: %v", decodeErr)
	default:
		detail = firstLine(stderr.String())
		if detail == "" {
			detail = waitErr.Error()
		}
	}
	if read == 0 {
		return fmt.Errorf("op item get failed: %s", detail)
	}
	if ix.incomplete != "" {
		ix.incomplete += "; "
	}
	if account.ID != "" {
		detail = accountLabel(account) + ": " + detail
	}
	ix.incomplete += detail
	return nil
}

// decodeItems accepts both shapes `op item get - --format json` emits — a
// JSON array, or a concatenated stream of objects (one per piped item) —
// and calls each for every item as soon as it is complete.
func decodeItems(r io.Reader, each func(opItem)) error {
	br := bufio.NewReader(r)
	first, err := peekNonSpace(br)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil // nothing at all: op said so on stderr
		}
		return err
	}
	dec := json.NewDecoder(br)
	if first == '[' {
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	for dec.More() {
		var it opItem
		if err := dec.Decode(&it); err != nil {
			return err
		}
		each(it)
	}
	return nil
}

// peekNonSpace returns the first non-whitespace byte without consuming it.
func peekNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\n', '\r', '\t':
			continue
		}
		return b, br.UnreadByte()
	}
}

// add indexes one item's concealed fields, pinning each reference to
// accountID ("" for an unpinned pass). A value present in several fields
// settles on the lowest (vault id, item id, first field) — the choice is
// cosmetic (same value, same secret), but it must not change between
// runs of the same vault state, and the stream's own order is op's to
// change.
func (ix *Index) add(it opItem, accountID string) {
	ix.read++
	for _, f := range it.Fields {
		if f.Type != "CONCEALED" || len(f.Value) < MinLinkableValueLen {
			continue
		}
		if it.Vault.ID == "" || it.ID == "" || f.ID == "" {
			continue // no rename-proof reference to build; skip rather than store a fragile one
		}
		sum := sha256.Sum256([]byte(f.Value))
		if held, taken := ix.byHash[sum]; taken && !earlier(it, held) {
			continue
		}
		name := f.Reference
		if name == "" {
			name = fmt.Sprintf("op://%s/%s/%s", it.Vault.Name, it.Title, f.Label)
		}
		ix.byHash[sum] = indexed{
			IndexEntry: IndexEntry{
				IDRef:   PinAccount(fmt.Sprintf("op://%s/%s/%s", it.Vault.ID, it.ID, f.ID), accountID),
				NameRef: name,
			},
			vaultID: it.Vault.ID,
			itemID:  it.ID,
		}
	}
}

// earlier reports whether it sorts before the item held holds — strictly,
// so a second field of the same item never displaces the first.
func earlier(it opItem, held indexed) bool {
	if it.Vault.ID != held.vaultID {
		return it.Vault.ID < held.vaultID
	}
	return it.ID < held.itemID
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
