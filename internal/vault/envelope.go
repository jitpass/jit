// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import "fmt"

// envelope is the on-disk JSON shape for a single .enc file, matching
// RFC.md Pillar II's schema exactly: a per-secret Data Encryption Key
// (DEK), itself wrapped once per recipient (Phase 1 has exactly one: this
// device), protects the actual payload.
type envelope struct {
	Version int `json:"version"`
	// CreatedUnix is when a secret was first stored at this path and
	// UpdatedUnix when it was last overwritten (version 2+, so both are
	// omitempty for version-1 files). Set preserves CreatedUnix across
	// overwrites, which is what lets "this key hasn't been rotated since
	// January" be answered at all. Plaintext on disk — timestamps aren't
	// secret — but NOT tamperable: both are bound into the payload's AAD
	// (envelopeAAD), so editing them makes decryption fail rather than
	// silently backdating a stale credential.
	CreatedUnix int64 `json:"created_unix,omitempty"`
	UpdatedUnix int64 `json:"updated_unix,omitempty"`
	// Class, GroupID, and Origin are birth-time provenance (version 3+, so
	// all omitempty for older files). Class is the semantic source kind
	// (ClassDotenv, ClassMCP, …); GroupID is a surrogate key every secret
	// imported together from one source shares, so "these 14 came from the
	// same .env" survives a folder rename or file move the way the raw path
	// never could; Origin is the best-effort, normalized source path the
	// secret was last seen at, allowed to go stale (OriginSeenUnix stamps
	// when it was recorded). All three are BIRTH-immutable: Set preserves
	// them across a rotation (a rotated value is the same secret, from the
	// same place), so they never need to be re-derived. Like the timestamps
	// they are plaintext on disk but AAD-bound (envelopeAAD), so editing
	// them fails decryption rather than silently rewriting provenance.
	Class          string `json:"class,omitempty"`
	GroupID        string `json:"group_id,omitempty"`
	Origin         string `json:"origin,omitempty"`
	OriginSeenUnix int64  `json:"origin_seen_unix,omitempty"`
	// Storage says what the PAYLOAD is (version 4+): "" means the payload
	// is the secret value itself, StorageOpRef means it is a 1Password
	// secret reference (an op:// URI) that Get resolves through the
	// Vault's RefResolver at read time. Unlike the provenance fields it is
	// NOT birth-immutable — it describes the current payload, and a
	// literal Set over a linked path deliberately clears it (the user
	// replaced the pointer with a value). It is deliberately an explicit,
	// AAD-bound marker rather than a payload sniff: a stored value that
	// happens to look like "op://…" must never silently morph into a
	// resolver call, and flipping the marker on disk (either direction)
	// must fail decryption rather than change what Get does.
	Storage string `json:"storage,omitempty"`
	// ExpiresUnix is when the PAYLOAD stops being valid (version 5+): the
	// stamp a temporary credential arrived with — an AWS session minted by
	// an SSO CLI carries its own expiry — copied out of the value so a
	// listing can answer "is this session still live" without decrypting
	// anything (jit status is prompt-free by design, so it may read
	// metadata and never a value). Zero means no known expiry: a
	// long-lived key, or any secret written before version 5 — never
	// "expired". Unlike the provenance fields it is NOT birth-immutable: a
	// rotation replaces it, because a re-minted session has a new end, and
	// a Set that carries no stamp clears it, because a value with no known
	// end has none. Plaintext on disk (the SDKs receive the same stamp in
	// the clear) but AAD-bound, so an edited stamp fails decryption rather
	// than resurrecting a dead session or hiding a live one.
	ExpiresUnix int64 `json:"expires_unix,omitempty"`
	// Recipients maps a recipient ID (this device's hostname in Phase 1;
	// Phase 2 adds real multi-recipient sharing, RFC.md §5.2) to that
	// recipient's hex-encoded wrapped DEK.
	Recipients map[string]string `json:"recipients"`
	// Payload is the hex-encoded (nonce || ciphertext) of the secret value,
	// AES-256-GCM sealed under the DEK — with envelopeAAD as the additional
	// authenticated data for version 2+, nothing for version 1.
	Payload string `json:"payload"`
}

// wrappedDEKFor selects the hex-encoded wrapped DEK this device should use to
// open the envelope — the single recipient-resolution rule Get and Verify
// MUST agree on (a doctor that validated a recipient Get never reads would
// false-flag a shareable envelope as corrupt, or pass one this device can't
// actually open). It is deliberately the only place that rule lives.
//
// Exact match first. Failing that, a single-recipient envelope is still worth
// returning: every envelope this vault has ever written has exactly one
// recipient (Set always writes one), so a mismatch there almost always means
// the machine's IDENTIFIER changed, not the machine — envelopes written before
// EnsureDeviceID existed are keyed by os.Hostname(), which drifts with a Mac
// rename or even a DHCP-supplied name. If the wrapped DEK genuinely came from
// a different machine, UnwrapKey fails at the KeyWrapper layer anyway (the MEK
// won't match), so returning it costs nothing and never decrypts anything this
// device couldn't already decrypt. A multi-recipient envelope with no match,
// by contrast, is genuinely not for this device and is reported as such.
func (env envelope) wrappedDEKFor(recipientID, path string) (string, error) {
	if w, ok := env.Recipients[recipientID]; ok {
		return w, nil
	}
	switch len(env.Recipients) {
	case 0:
		return "", fmt.Errorf("corrupt envelope %s: no recipients, its wrapped key is gone", path)
	case 1:
		for _, w := range env.Recipients {
			return w, nil
		}
	}
	return "", fmt.Errorf("no key for this device (%s) in %s, it was likely encrypted on a different machine", recipientID, path)
}

const (
	// envelopeVersionAADLess is the original schema: no metadata, payload
	// sealed with no additional authenticated data. Never written anymore,
	// readable forever — vaults full of v1 files must keep decrypting
	// without a migration step.
	envelopeVersionAADLess = 1
	// envelopeVersionMetaOnly is the second schema: created/updated
	// timestamps bound into the AAD, no provenance. Never written anymore
	// (Set writes v4), readable forever, same as v1.
	envelopeVersionMetaOnly = 2
	// envelopeVersionProvenance is the third schema: v2's metadata plus
	// class/group/origin provenance, all AAD-bound. Never written anymore
	// (Set writes v4), readable forever, same as v1 and v2.
	envelopeVersionProvenance = 3
	// envelopeVersionStorage is the fourth schema: v3's provenance plus
	// the storage marker (see envelope.Storage), all AAD-bound. Never
	// written anymore (Set writes v5), readable forever, same as v1–v3.
	envelopeVersionStorage = 4
	// envelopeVersion is what Set writes today: v4 plus the expiry stamp
	// (see envelope.ExpiresUnix), AAD-bound like everything before it.
	envelopeVersion = 5
)

// StorageOpRef marks an envelope whose payload is a 1Password secret
// reference (an op:// URI) rather than the secret value itself — see
// envelope.Storage and design/1password-adapter.md. The reference is
// encrypted and consent-gated exactly like a literal value: an op://
// path names the user's 1Password credential map, and gating its unwrap
// is what keeps per-process consent meaningful for linked secrets.
const StorageOpRef = "op-ref"

// Class values name the semantic source a secret came from — the durable,
// AAD-bound answer to "is this from a .env, an .mcp.json, my shell rc?".
// One migrator stamps one class; a manual `jit vault set` stamps ClassManual.
// An empty class means unknown (a v1/v2 secret written before provenance
// existed), never an error.
const (
	ClassManual    = "manual"
	ClassDotenv    = "dotenv"
	ClassShell     = "shell"
	ClassMCP       = "mcp"
	ClassTfvars    = "tfvars"
	ClassTerraform = "terraform"
	ClassAWS       = "aws"
	ClassDocker    = "docker"
	ClassGCP       = "gcp"
	ClassSOPS      = "sops"
	ClassNpmrc     = "npmrc"
	ClassPypirc    = "pypirc"
	ClassGit       = "git"
	ClassNetrc     = "netrc"
	ClassKube      = "kube"
	ClassWrap      = "wrap"
	// ClassLooseFile is a bare secret migrated out of a file the user named
	// explicitly to `jit migrate <path>` — a token in a plain file (token.txt)
	// that matches none of the structured formats above. Origin is the file
	// path; the whole file was the secret.
	ClassLooseFile = "loose_file" // #nosec G101 -- provenance class label, not a credential
	// ClassK8sSecret is a value migrated out of a Kubernetes Secret
	// manifest's data:/stringData: block (distinct from ClassKube, which is
	// a kubeconfig credential). Origin is the manifest path.
	ClassK8sSecret = "k8s_secret" // #nosec G101 -- provenance class label, not a credential
	// ClassOnePassword is a 1Password reference linked from nothing (`jit
	// vault link`, manual or bulk): born as a link, its only source IS
	// 1Password. A secret that `jit migrate` links keeps its migrator's
	// class instead — it was born in that file, and envelope.Storage alone
	// says how it is fulfilled. See design/1password-adapter.md.
	ClassOnePassword = "1password"
	// ClassShellHistory is a credential redacted out of a shell history file
	// by `jit migrate` (distinct from ClassShell, which is an export line
	// moved out of a shell rc file). Origin is the history file path. These
	// are quarantine as much as storage: the value was typed at a prompt and
	// recorded, so the durable fix is rotation — the vault copy exists so the
	// redaction is reversible and the token recoverable until then.
	ClassShellHistory = "shell_history" // #nosec G101 -- provenance class label, not a credential
)

// envelopeAAD is the additional authenticated data a version-2+ payload is
// sealed under: the secret's own vault path plus the envelope's version and
// timestamps. Binding the path is what makes a swapped .enc file fail
// closed — before this, copying stripe/live-key.enc over stripe/dev-key.enc
// decrypted cleanly and handed the live key to whatever asked for the dev
// one, with nothing anywhere able to notice. Binding the metadata keeps the
// plaintext-on-disk timestamps honest (see envelope.CreatedUnix).
//
// The path needs no escaping in this colon-joined string: sanitizeSecretPath
// admits only [A-Za-z0-9_.-] and '/', so a colon can never appear in it and
// the encoding is unambiguous.
//
// The AAD is version-shaped: a v5 payload was sealed under a string that
// appends class:group:storage:expires:origin, a v4 payload under the shape
// that appends class:group:storage:origin, a v3 payload under
// class:group:origin, a v2 payload under the four-field string that
// predates them all. Get MUST reconstruct whichever the stored version used,
// so the branch here is keyed on version, NOT on whether the newer fields
// happen to be non-empty. class, group_id, storage and the expiry never
// contain a colon (fixed vocabulary / hex id / integer); origin can in
// principle, which is why origin stays the LAST field in every version's
// shape — v4 inserts storage and v5 inserts expires BEFORE origin, not
// after it — so everything past the final delimiter is origin and the
// encoding stays unambiguous.
func envelopeAAD(path string, version int, createdUnix, updatedUnix int64, class, groupID, origin, storage string, expiresUnix int64) []byte {
	switch {
	case version >= envelopeVersion:
		return fmt.Appendf(nil, "jit-envelope:%d:%s:%d:%d:%s:%s:%s:%d:%s", version, path, createdUnix, updatedUnix, class, groupID, storage, expiresUnix, origin)
	case version >= envelopeVersionStorage:
		return fmt.Appendf(nil, "jit-envelope:%d:%s:%d:%d:%s:%s:%s:%s", version, path, createdUnix, updatedUnix, class, groupID, storage, origin)
	case version >= envelopeVersionProvenance:
		return fmt.Appendf(nil, "jit-envelope:%d:%s:%d:%d:%s:%s:%s", version, path, createdUnix, updatedUnix, class, groupID, origin)
	}
	return fmt.Appendf(nil, "jit-envelope:%d:%s:%d:%d", version, path, createdUnix, updatedUnix)
}
