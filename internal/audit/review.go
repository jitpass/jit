// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"time"
)

// A review mark is the user saying "I looked at this one, it is not live"
// about a finding scan keeps reporting: a real-looking key in a test file
// or a README. `jit review` writes marks, and a later scan drops a
// finding that matches one, counting it in ScanSummary.Reviewed instead.
//
// A mark matches the VALUE in a file, never its line: an edit that moves
// the line keeps the mark, and a changed value is a new finding. It holds
// an HMAC of the value's digest, never the value, keyed by a random key
// kept in the same owner-only file. The value sits in plaintext in the
// named file anyway, so the key is not there to guard the file from its
// own reader; it keeps the list of marks from being a list of digests
// that could be matched against values seen anywhere else.
//
// Marks are not offered for vault copies or agent-cache copies: those are
// copies of secrets jit already holds, and the fix is Redact or rotate.

// ReviewMark is one reviewed finding as the store keeps it.
type ReviewMark struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Line       *int   `json:"line,omitempty"`
	Type       string `json:"finding_type"`
	Label      string `json:"label"`
	ReviewedAt int64  `json:"reviewed_at"`
}

// ReviewStore is the file of marks: `scan-reviewed.json` in jit's
// Application Support folder.
type ReviewStore struct {
	path  string
	Key   string       `json:"key"`
	Marks []ReviewMark `json:"marks"`
}

// LoadReviewStore reads the store at path. A missing file is an empty
// store; a new key is made on the first Save.
func LoadReviewStore(path string) (*ReviewStore, error) {
	s := &ReviewStore{path: path}
	data, err := os.ReadFile(path) // #nosec G304 -- jit's own state file
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.path = path
	return s, nil
}

// Encode is the store as its file holds it, the marks in path order.
// Writing it is the CLI's job (scanreview.go): this package never writes.
func (s *ReviewStore) Encode() ([]byte, error) {
	if err := s.ensureKey(); err != nil {
		return nil, err
	}
	sort.Slice(s.Marks, func(i, j int) bool {
		if s.Marks[i].Path != s.Marks[j].Path {
			return s.Marks[i].Path < s.Marks[j].Path
		}
		return lineOf(s.Marks[i].Line) < lineOf(s.Marks[j].Line)
	})
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Path is the file the store was loaded from.
func (s *ReviewStore) Path() string { return s.path }

func (s *ReviewStore) ensureKey() error {
	if s.Key != "" {
		return nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	s.Key = hex.EncodeToString(b)
	return nil
}

// maxIdentityRead bounds the file read that identifies a finding with no
// value of its own; a larger file is not markable.
const maxIdentityRead = 5 << 20

// contentDigest is what a finding is about, as a digest: its value; for a
// file-level finding (an env file's), every credential it judged, or, when
// it judged none, the file's whole content. So a mark on a file ends when
// anything in the file changes, and a key added to a reviewed .env is
// reported. "" when there is nothing to identify it by: not markable.
func contentDigest(f Finding) string {
	if f.rawValueDigest != "" {
		return f.rawValueDigest
	}
	h := sha256.New()
	if len(f.claimedRawValues) > 0 {
		values := make([]string, 0, len(f.claimedRawValues))
		for _, cv := range f.claimedRawValues {
			values = append(values, cv.Key+"="+cv.Value)
		}
		sort.Strings(values)
		for _, v := range values {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
		return "claimed:" + hex.EncodeToString(h.Sum(nil))
	}
	info, err := os.Stat(f.FilePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxIdentityRead {
		return ""
	}
	data, err := os.ReadFile(f.FilePath) // #nosec G304 -- the file the finding names, read to identify it
	if err != nil {
		return ""
	}
	h.Write(data)
	return "file:" + hex.EncodeToString(h.Sum(nil))
}

// markID is the finding's identity under the store's key: its file, its
// type and its content digest. "" when the finding cannot be identified.
func (s *ReviewStore) markID(f Finding) string {
	digest := contentDigest(f)
	if digest == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(s.Key))
	mac.Write([]byte(f.FilePath))
	mac.Write([]byte{0})
	mac.Write([]byte(f.FindingType))
	mac.Write([]byte{0})
	mac.Write([]byte(digest))
	return hex.EncodeToString(mac.Sum(nil))
}

// Reviewable says whether a mark may be set on f. Copies of vaulted or
// cached secrets may not (a finding inside an agent cache has a cache
// area): Redact or rotation fixes those. Nor may a finding jit fixes
// itself: Protect is the answer to it, not a mark.
func Reviewable(f Finding) bool {
	return f.FindingType != FindingTypeVaultCopy && f.FindingType != FindingTypeAgentCachedSecret && f.CacheArea == "" &&
		f.Remedy != RemedyMigrate && f.Remedy != RemedyWrap
}

// ErrNotReviewable is Mark's answer for a finding a mark does not fit.
var ErrNotReviewable = errors.New("not reviewable")

// Mark records f as reviewed at `at` and returns its mark, the one already
// there when f was marked before.
func (s *ReviewStore) Mark(f Finding, label string, at time.Time) (ReviewMark, error) {
	if !Reviewable(f) {
		return ReviewMark{}, fmt.Errorf("%s: %w: redact, rotate or protect it instead", f.FilePath, ErrNotReviewable)
	}
	if err := s.ensureKey(); err != nil {
		return ReviewMark{}, err
	}
	id := s.markID(f)
	if id == "" {
		return ReviewMark{}, fmt.Errorf("%s: %w: jit cannot tell later whether it changed", f.FilePath, ErrNotReviewable)
	}
	for _, m := range s.Marks {
		if m.ID == id {
			return m, nil
		}
	}
	m := ReviewMark{ID: id, Path: f.FilePath, Line: f.Line, Type: f.FindingType, Label: label, ReviewedAt: at.Unix()}
	s.Marks = append(s.Marks, m)
	return m, nil
}

// UnmarkIDs removes the marks with these ids and returns them.
func (s *ReviewStore) UnmarkIDs(ids []string) []ReviewMark {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var kept, gone []ReviewMark
	for _, m := range s.Marks {
		if want[m.ID] {
			gone = append(gone, m)
		} else {
			kept = append(kept, m)
		}
	}
	s.Marks = kept
	return gone
}

// Unmark removes the marks on any of paths, the spellings of one file
// (on that line, when line is set), and returns them.
func (s *ReviewStore) Unmark(paths []string, line *int) []ReviewMark {
	var kept, gone []ReviewMark
	for _, m := range s.Marks {
		if slices.Contains(paths, m.Path) && (line == nil || lineOf(m.Line) == *line) {
			gone = append(gone, m)
			continue
		}
		kept = append(kept, m)
	}
	s.Marks = kept
	return gone
}

// Reviewed reports the mark f matches, if any.
func (s *ReviewStore) Reviewed(f Finding) (ReviewMark, bool) {
	if s == nil || s.Key == "" || !Reviewable(f) {
		return ReviewMark{}, false
	}
	// Only a file some mark names is worth identifying: that can read it.
	if !slices.ContainsFunc(s.Marks, func(m ReviewMark) bool { return m.Path == f.FilePath }) {
		return ReviewMark{}, false
	}
	id := s.markID(f)
	if id == "" {
		return ReviewMark{}, false
	}
	for _, m := range s.Marks {
		if m.ID == id {
			return m, true
		}
	}
	return ReviewMark{}, false
}

// dropReviewed removes the findings the store marks, or, on an
// --unfiltered run, keeps them tagged with the date they were reviewed,
// the way every other filter shows what it hid. It returns how many it
// left out: none on an --unfiltered run, which leaves nothing out.
func dropReviewed(cfg Config, findings []Finding) ([]Finding, int) {
	if cfg.Reviewed == nil {
		return findings, 0
	}
	n := 0
	kept := findings[:0]
	for _, f := range findings {
		m, ok := cfg.Reviewed.Reviewed(f)
		if !ok {
			kept = append(kept, f)
			continue
		}
		if cfg.Unfiltered {
			f.UnfilteredOnly = true
			f.UnfilteredReason = "you marked it reviewed on " + time.Unix(m.ReviewedAt, 0).Format("2006-01-02")
			kept = append(kept, f)
			continue
		}
		n++
	}
	return kept, n
}

// reviewedLine says the report leaves findings out, so a clean report
// is never read as a clean machine. Empty when nothing matched a mark.
func reviewedLine(summary ScanSummary) string {
	switch summary.Reviewed {
	case 0:
		return ""
	case 1:
		return "  1 finding you marked reviewed is left out; jit review --list shows it\n\n"
	default:
		return fmt.Sprintf("  %d findings you marked reviewed are left out; jit review --list shows them\n\n", summary.Reviewed)
	}
}

func lineOf(l *int) int {
	if l == nil {
		return 0
	}
	return *l
}
