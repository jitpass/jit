// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
)

func TestHistoryLogRoundTrip(t *testing.T) {
	var stderr bytes.Buffer
	h := newHistoryLog(t.TempDir(), &stderr)

	events := []agent.SessionEvent{
		{UnixTime: 100, Kind: agent.KindStart, Cause: "build abc123"},
		{UnixTime: 200, Kind: agent.KindUnlock, Op: agent.OpUnwrap, By: "jit run --profile x", ByPID: 42, LaunchedBy: "claude", Labels: []string{"stripe/live-key"}},
		{UnixTime: 250, Kind: agent.KindUse, Op: agent.OpUnwrap, By: "jit run --profile x", Count: 7, Labels: []string{"a/b", "c/d"}},
		{UnixTime: 300, Kind: agent.KindLock, Cause: "15m0s idle timeout"},
	}
	for _, e := range events {
		h.append(e)
	}

	got := h.load(agent.MaxSessionEvents)
	if len(got) != len(events) {
		t.Fatalf("load returned %d events, want %d (stderr: %s)", len(got), len(events), stderr.String())
	}
	for i := range events {
		// reflect.DeepEqual, not ==: SessionEvent carries a Labels slice now.
		if !reflect.DeepEqual(got[i], events[i]) {
			t.Errorf("event %d = %+v, want %+v, a restored event must carry every field it was recorded with", i, got[i], events[i])
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr output: %s", stderr.String())
	}

	// The file must not be readable by other users: it records who ran
	// what and when, same sensitivity as agent.log.
	fi, err := os.Stat(h.path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("history file mode = %o, want 0600", perm)
	}
}

// A crash mid-append leaves a torn final line; a curious user may leave
// anything at all. Neither must cost the events that ARE intact.
func TestHistoryLogSkipsMalformedLines(t *testing.T) {
	var stderr bytes.Buffer
	h := newHistoryLog(t.TempDir(), &stderr)

	h.append(agent.SessionEvent{UnixTime: 100, Kind: agent.KindUnlock})
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteString("{\"unix_time\": 150, \"kind\"\nnot json at all\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	_ = f.Close()
	h.append(agent.SessionEvent{UnixTime: 200, Kind: agent.KindLock, Cause: "explicit lock"})

	got := h.load(agent.MaxSessionEvents)
	if len(got) != 2 {
		t.Fatalf("load returned %d events, want the 2 intact ones despite garbage between them: %+v", len(got), got)
	}
	if got[0].UnixTime != 100 || got[1].UnixTime != 200 {
		t.Errorf("events = %+v, want the intact ones in append order", got)
	}
}

func TestHistoryLogLoadCapsToNewest(t *testing.T) {
	var stderr bytes.Buffer
	h := newHistoryLog(t.TempDir(), &stderr)
	for i := 0; i < 10; i++ {
		h.append(agent.SessionEvent{UnixTime: int64(i), Kind: agent.KindUnlock})
	}
	got := h.load(3)
	if len(got) != 3 || got[0].UnixTime != 7 || got[2].UnixTime != 9 {
		t.Errorf("load(3) = %+v, want the NEWEST 3 in append order, seeding must favor recent history", got)
	}
}

// trim must bound the file while keeping the newest half intact on a line
// boundary — losing the oldest events is the point; losing recent ones or
// corrupting a line would defeat the file's purpose.
func TestHistoryLogTrimKeepsNewestHalf(t *testing.T) {
	var stderr bytes.Buffer
	h := newHistoryLog(t.TempDir(), &stderr)

	// Build a file safely past the cap with numbered events.
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	var n int64
	for size := int64(0); size <= historyMaxBytes; n++ {
		line := fmt.Sprintf("{\"unix_time\": %d, \"kind\": \"unlock\", \"by\": \"%s\"}\n", n, string(bytes.Repeat([]byte{'x'}, 100)))
		if _, err := f.WriteString(line); err != nil {
			t.Fatalf("WriteString: %v", err)
		}
		size += int64(len(line))
	}
	_ = f.Close()

	h.trim()

	fi, err := os.Stat(h.path)
	if err != nil {
		t.Fatalf("Stat after trim: %v", err)
	}
	if fi.Size() > historyMaxBytes/2 {
		t.Errorf("file is %d bytes after trim, want <= %d", fi.Size(), historyMaxBytes/2)
	}
	got := h.load(10 * agent.MaxSessionEvents)
	if len(got) == 0 {
		t.Fatal("no events survived the trim")
	}
	if got[len(got)-1].UnixTime != n-1 {
		t.Errorf("newest surviving event is %d, want %d, trim must drop the OLD end", got[len(got)-1].UnixTime, n-1)
	}
	for i := 1; i < len(got); i++ {
		if got[i].UnixTime != got[i-1].UnixTime+1 {
			t.Fatalf("gap in surviving events at %d (%d then %d), trim cut somewhere other than a line boundary", i, got[i-1].UnixTime, got[i].UnixTime)
		}
	}

	// Under the cap: trim must be a no-op, not a rewrite.
	before := fi.Size()
	h.trim()
	fi, _ = os.Stat(h.path)
	if fi.Size() != before {
		t.Errorf("trim on an under-cap file changed its size from %d to %d", before, fi.Size())
	}
}

func TestHistoryLogLoadMissingFile(t *testing.T) {
	var stderr bytes.Buffer
	h := newHistoryLog(t.TempDir(), &stderr)
	if got := h.load(agent.MaxSessionEvents); got != nil {
		t.Errorf("load on a never-written file = %+v, want nil", got)
	}
	if stderr.Len() != 0 {
		t.Errorf("a missing history file logged %q, first-ever start is normal, not an error", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.path))); err != nil {
		t.Fatalf("temp dir: %v", err)
	}
}

// Lines written before the agent redacted By at the source (the pre-fix
// format) can hold a caller's raw secret for years — the file keeps ~10k
// events. Loading must scrub them with the same masking the agent now applies
// on record, so a poisoned legacy line stops leaking through `jit agent
// history`, the seeded ring, and `jit audit` alike.
func TestHistoryLogLoadScrubsLegacyPlaintextBy(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	dir := t.TempDir()
	h := newHistoryLog(dir, nil)
	legacy := fmt.Sprintf(
		`{"unix_time":100,"kind":"unlock","op":"unwrap","by":"jit run -- curl -H %s","by_pid":42}
{"unix_time":200,"kind":"unlock","op":"wrap","by":"jit vault set stripe/live-key hunter2","by_pid":43}
`, secret)
	if err := os.WriteFile(filepath.Join(dir, historyFileName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	got := h.load(agent.MaxSessionEvents)
	if len(got) != 2 {
		t.Fatalf("load returned %d events, want 2", len(got))
	}
	if strings.Contains(got[0].By, secret) {
		t.Errorf("By = %q still carries a legacy line's raw credential", got[0].By)
	}
	if strings.Contains(got[1].By, "hunter2") {
		t.Errorf("By = %q still carries a legacy vault-set value", got[1].By)
	}
	if !strings.Contains(got[1].By, "stripe/live-key") {
		t.Errorf("By = %q, want the path kept while scrubbing the value", got[1].By)
	}
}

// scrubLegacy is the half of the legacy story load's display scrub cannot
// deliver: the plaintext must leave the DISK, not just the screen — the file
// is readable by any same-user process and lands in every backup. After the
// rewrite the secret bytes are gone, the events still parse, and a line that
// was already clean survives byte-for-byte (so fields written by a newer
// binary than this one are not lost to a re-marshal).
func TestHistoryLogScrubLegacyRemovesPlaintextFromDisk(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	dir := t.TempDir()
	h := newHistoryLog(dir, nil)
	cleanLine := `{"unix_time":50,"kind":"start","cause":"build test","future_field":"kept"}`
	legacy := cleanLine + "\n" + fmt.Sprintf(
		`{"unix_time":100,"kind":"unlock","op":"unwrap","by":"jit run -- curl -H token=%s","by_pid":42}
{"unix_time":200,"kind":"unlock","op":"wrap","by":"jit vault set stripe/live-key hunter2","by_pid":43}
`, secret)
	if err := os.WriteFile(filepath.Join(dir, historyFileName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	h.scrubLegacy()

	raw, err := os.ReadFile(filepath.Join(dir, historyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("secret still on disk after scrubLegacy:\n%s", raw)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("weak vault-set value still on disk after scrubLegacy:\n%s", raw)
	}
	if !strings.Contains(string(raw), "stripe/live-key") {
		t.Errorf("scrubLegacy lost the vault path:\n%s", raw)
	}
	if !strings.Contains(string(raw), cleanLine) {
		t.Errorf("already-clean line was rewritten (unknown fields would be lost):\n%s", raw)
	}
	if got := h.load(agent.MaxSessionEvents); len(got) != 3 {
		t.Errorf("load returned %d events after scrub, want 3", len(got))
	}
}

// TestTrimHistoryPeriodically pins the mid-run cap: the 2MB trim used to run
// only at service start, so anything that grew the file — launchd keeps one
// process alive for weeks — ran unbounded until the NEXT restart.
func TestTrimHistoryPeriodically(t *testing.T) {
	h := newHistoryLog(t.TempDir(), io.Discard)
	line := []byte(`{"unix_time":1,"kind":"unlock"}` + "\n")
	big := bytes.Repeat(line, historyMaxBytes/len(line)+64)
	if err := os.WriteFile(h.path, big, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go trimHistoryPeriodically(ctx, h, 5*time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(h.path); err == nil && fi.Size() <= historyMaxBytes {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	fi, _ := os.Stat(h.path)
	t.Fatalf("the periodic trim never brought the file under the cap (size %d, cap %d)", fi.Size(), historyMaxBytes)
}
