// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Account pinning. An op:// reference names a vault, an item and a field
// but NOT an account, and op resolves every reference against ONE
// account — `--account`, else OP_ACCOUNT, else whichever it signed in to
// most recently. On a Mac with two accounts (a personal one and an
// employer's) that default flips with ordinary use, and a link made
// under one account then fails with "isn't a vault in this account"
// under the other. Found live 2026-09-05 with exactly that pair.
//
// So a link jit creates carries the account it was made against, as a
// query parameter on the stored reference — `op://v/i/f?account=<id>`,
// the same slot op itself uses for `?attribute=otp`. op ignores the
// parameter (verified: identical behavior with and without it), the
// resolver strips it and passes `--account` instead, and every other
// consumer of the stored string (export, doctor's sweep, `vault get`'s
// JSON) carries it along untouched. The id is the ACCOUNT uuid, not the
// user's: it names the account itself, which is what the vault ids
// inside the reference belong to.

// accountParam is the query key carrying the pin.
const accountParam = "account"

// Account is one signed-in 1Password account as `op account list` reports
// it. ID is the account uuid (the pin); the rest identify it to a person
// and match OP_ACCOUNT.
type Account struct {
	ID        string `json:"account_uuid"`
	UserID    string `json:"user_uuid"`
	URL       string `json:"url"`
	Shorthand string `json:"shorthand"`
	Email     string `json:"email"`
}

// Accounts lists the accounts op knows on this machine. Reads op's own
// config through the app integration — no authorization prompt, no
// secret — and is bounded short because a health probe must never hang.
func (r *Resolver) Accounts() ([]Account, error) {
	bin, err := r.bin()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runOp(ctx, bin, nil, "account", "list", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("op account list failed: %w", err)
	}
	var accounts []Account
	if err := json.Unmarshal(out, &accounts); err != nil {
		return nil, fmt.Errorf("op account list output not understood: %v", err)
	}
	return accounts, nil
}

// enumerationAccounts is the account set one enumeration covers: every
// signed-in account, unless OP_ACCOUNT names one — op's own scoping
// variable, honored here so a user with a large employer account beside
// a personal one can keep migrate to the one they mean. An OP_ACCOUNT
// that matches nothing, or a failed listing, yields nil: one unpinned
// pass under op's own default, today's behavior.
func (r *Resolver) enumerationAccounts() []Account {
	accounts, err := r.Accounts()
	if err != nil {
		return nil
	}
	return selectAccounts(accounts, os.Getenv("OP_ACCOUNT"))
}

// selectAccounts filters by OP_ACCOUNT the way op's --account matches:
// shorthand, sign-in address (with or without scheme), account id, user
// id — plus the email, which people also reach for.
func selectAccounts(all []Account, opAccount string) []Account {
	want := strings.TrimSpace(opAccount)
	if want == "" {
		return all
	}
	want = strings.ToLower(want)
	for _, a := range all {
		host := a.URL
		if u, err := url.Parse(a.URL); err == nil && u.Host != "" {
			host = u.Host
		}
		for _, cand := range []string{a.Shorthand, a.URL, host, a.ID, a.UserID, a.Email} {
			if cand != "" && strings.ToLower(cand) == want {
				return []Account{a}
			}
		}
	}
	return nil
}

// PinAccount returns ref carrying accountID as its account parameter,
// replacing any pin already present. An empty accountID returns ref
// unchanged.
func PinAccount(ref, accountID string) string {
	if accountID == "" {
		return ref
	}
	bare, _ := SplitAccount(ref)
	sep := "?"
	if strings.Contains(bare, "?") {
		sep = "&"
	}
	return bare + sep + accountParam + "=" + url.QueryEscape(accountID)
}

// SplitAccount separates the account pin from a reference: bare is the
// reference op receives (every other query parameter kept, in op's own
// order of no significance), accountID the pin or "". The path is never
// re-encoded — a name-form reference may carry spaces op accepts raw and
// url.URL.String would percent-escape.
func SplitAccount(ref string) (bare, accountID string) {
	i := strings.IndexByte(ref, '?')
	if i < 0 {
		return ref, ""
	}
	q, err := url.ParseQuery(ref[i+1:])
	if err != nil {
		return ref, ""
	}
	accountID = q.Get(accountParam)
	if accountID == "" {
		return ref, ""
	}
	q.Del(accountParam)
	if len(q) == 0 {
		return ref[:i], accountID
	}
	return ref[:i] + "?" + q.Encode(), accountID
}

// Pin resolves ref once and returns it pinned to the account it resolved
// in — `jit vault link`'s trial resolve, made account-aware. A ref
// already pinned is only test-resolved. Otherwise, with one account
// signed in the pin is that account; with several, each is tried in
// turn (op's own listing order) and the first that resolves wins, so a
// reference copied from either app window links correctly without the
// user knowing the account uuid. No accounts listed at all (op not
// configured) means one unpinned resolve and an unpinned link, as
// before. Every attempt can pop that account's authorization dialog.
func (r *Resolver) Pin(ref string) (string, error) {
	if _, pinned := SplitAccount(ref); pinned != "" {
		if _, err := r.ResolveRef(ref); err != nil {
			return "", err
		}
		return ref, nil
	}
	accounts, err := r.Accounts()
	if err != nil || len(accounts) == 0 {
		if _, err := r.ResolveRef(ref); err != nil {
			return "", err
		}
		return ref, nil
	}
	var firstErr error
	for _, a := range accounts {
		pinned := PinAccount(ref, a.ID)
		if _, err := r.ResolveRef(pinned); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return pinned, nil
	}
	if len(accounts) > 1 {
		return "", fmt.Errorf("%w (tried all %d signed-in accounts)", firstErr, len(accounts))
	}
	return "", firstErr
}
