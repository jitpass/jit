// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

// seedAuditFixtures plants a command record and an auth event under the fixture
// home's config root, the two durable files `jit audit` reads.
func seedAuditFixtures(t *testing.T, home string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	auditlog.New(root, nil).Append(auditlog.Record{
		UnixNano:   1000,
		Command:    "jit vault get",
		Args:       []string{"vault", "get", "stripe/live-key"},
		User:       "alice",
		UID:        501,
		PID:        4242,
		LaunchedBy: "claude",
		DurationMS: 120,
		Success:    true,
	})
	newHistoryLog(root, nil).append(agent.SessionEvent{
		UnixTime:   2000,
		Kind:       agent.KindUnlock,
		Op:         agent.OpUnwrap,
		By:         "jit vault get stripe/live-key",
		LaunchedBy: "claude",
		Labels:     []string{"stripe/live-key"},
		AuthMethod: "Touch ID or device passcode",
	})
}

// seedServeFixtures plants the two mount-read outcomes: a decoy handed to a
// process nobody granted anything to, and the real value handed to a tool
// inside a grant.
func seedServeFixtures(t *testing.T, home string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	h := newHistoryLog(root, nil)
	h.append(agent.SessionEvent{
		UnixTime: 5000, Kind: agent.KindServe, Op: agent.OpServeDecoy,
		By: "/usr/local/bin/node", ByPID: 48213, LaunchedBy: "Code",
		Labels: []string{"gcp"}, Count: 34,
		Cause: "no jit run grant or consent approval covered the reader",
	})
	h.append(agent.SessionEvent{
		UnixTime: 5100, Kind: agent.KindServe, Op: agent.OpServeReal,
		By: "/opt/homebrew/bin/terraform", ByPID: 48044, LaunchedBy: "claude",
		Labels: []string{"aws"}, Count: 1,
		Cause: "authorized by a jit run grant",
	})
}

// seedGrantFixtures plants a process grant's whole life in the durable trail,
// exactly as the agent emits it (grant.go): the disclosed approval that
// created it, a collapsed grant-served use, and the ending.
func seedGrantFixtures(t *testing.T, home string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	h := newHistoryLog(root, nil)
	h.append(agent.SessionEvent{
		UnixTime: 7000, Kind: agent.KindApproved, Op: agent.OpGrantCreate,
		By: "jit grant --process claude --profile jamf --for 8h", ByPID: 4242,
		Cause:      "let claude use 2 secrets (jamf) unattended for 8h",
		AuthMethod: "Touch ID or device passcode",
	})
	h.append(agent.SessionEvent{
		UnixTime: 7100, Kind: agent.KindUse, Op: agent.OpGrantUse,
		By: "jit run --profile jamf -- terraform plan", ByPID: 4300, LaunchedBy: "claude",
		Labels: []string{"jamf/api-user", "jamf/api-pass"}, Count: 2,
	})
	h.append(agent.SessionEvent{
		UnixTime: 7200, Kind: agent.KindGrantEnd, Op: "g-1234abcd",
		Cause:  "claude's grant expired",
		Labels: []string{"jamf/api-user", "jamf/api-pass"},
	})
}

// TestAuditCapturesGrantLifecycle drives the REAL command over a grant's
// whole recorded life: the approval and the ending must both surface under
// --kind grant (one filter shows a grant's full story), and the grant-served
// use must render distinguishably from an ordinary session use. This is the
// contract that makes the feature auditable at all — a standing, unattended
// credential channel whose serves or endings vanished from `jit audit` would
// be exactly the "trust feature that becomes an incident write-up" the
// design doc warns about.
func TestAuditCapturesGrantLifecycle(t *testing.T) {
	home := withFixtureHome(t)
	seedGrantFixtures(t, home)

	out, err := execAuditLogfmt(t, "--kind", "grant")
	if err != nil {
		t.Fatalf("jit audit --kind grant: %v", err)
	}
	for _, want := range []string{
		"status=approved",
		`reason="let claude use 2 secrets (jamf) unattended for 8h"`,
		"status=ended",
		"grant=g-1234abcd",
		`reason="claude's grant expired"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--kind grant missing %q, got:\n%s", want, out)
		}
	}

	out, err = execAuditLogfmt(t, "--kind", "use")
	if err != nil {
		t.Fatalf("jit audit --kind use: %v", err)
	}
	for _, want := range []string{
		`op="read a secret via grant"`, // OpGrantUse through agent.DescribeUse — not an ordinary session use
		"count=2",
		"parent=claude",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--kind use missing %q for the grant-served use, got:\n%s", want, out)
		}
	}

	// The secret filter must reach a grant serve's labels like any other use.
	out, err = execAuditLogfmt(t, "--secret", "jamf/api-pass")
	if err != nil {
		t.Fatalf("jit audit --secret: %v", err)
	}
	if !strings.Contains(out, `op="read a secret via grant"`) || !strings.Contains(out, "status=ended") {
		t.Errorf("--secret jamf/api-pass should match both the grant serve and the ending, got:\n%s", out)
	}
}

// A decoy read is the honeytoken-shaped signal the mount design produces on
// every read and, before this, discarded: it must render as its own kind, name
// the reader and its launcher, and say why that reader got a fake.
func TestAuditRendersDecoyServe(t *testing.T) {
	home := withFixtureHome(t)
	seedServeFixtures(t, home)

	out, err := execAuditLogfmt(t)
	if err != nil {
		t.Fatalf("jit audit: %v", err)
	}
	for _, want := range []string{
		"kind=serve", "status=decoy", "mount=gcp", "count=34",
		"reader_pid=48213", "parent=Code",
		`reason="no jit run grant or consent approval covered the reader"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("decoy serve line missing %q, got:\n%s", want, out)
		}
	}
}

// The counterpart fact a grant approval can never supply: the credential was
// not just authorized, it was actually read, by this program.
func TestAuditRendersRealServe(t *testing.T) {
	home := withFixtureHome(t)
	seedServeFixtures(t, home)

	out, err := execAuditLogfmt(t, "--status", "real")
	if err != nil {
		t.Fatalf("jit audit --status real: %v", err)
	}
	if !strings.Contains(out, "status=real") || !strings.Contains(out, "mount=aws") {
		t.Errorf("--status real dropped the real serve, got:\n%s", out)
	}
	if strings.Contains(out, "status=decoy") {
		t.Errorf("--status real leaked a decoy serve, got:\n%s", out)
	}
}

// --status decoy is the tripwire query. It must narrow to decoy serves and
// nothing else, including excluding the real serves of the same kind.
func TestAuditFilterByStatusDecoy(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	seedServeFixtures(t, home)

	out, err := execAuditLogfmt(t, "--status", "decoy")
	if err != nil {
		t.Fatalf("jit audit --status decoy: %v", err)
	}
	if !strings.Contains(out, "status=decoy") {
		t.Errorf("--status decoy dropped the decoy serve, got:\n%s", out)
	}
	for _, unwanted := range []string{"status=real", "kind=cmd", "kind=unlock"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("--status decoy leaked %q, got:\n%s", unwanted, out)
		}
	}
}

func TestAuditFilterByKindServe(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	seedServeFixtures(t, home)

	out, err := execAuditLogfmt(t, "--kind", "serve")
	if err != nil {
		t.Fatalf("jit audit --kind serve: %v", err)
	}
	if n := strings.Count(out, "kind=serve"); n != 2 {
		t.Errorf("--kind serve showed %d serve lines, want 2, got:\n%s", n, out)
	}
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--kind serve leaked a command line, got:\n%s", out)
	}
}

// --parent is what makes this worth having: "what did the things Claude
// launched actually read". It must reach serve events, not only auth ones.
func TestAuditFilterByParentReachesServes(t *testing.T) {
	home := withFixtureHome(t)
	seedServeFixtures(t, home)

	out, err := execAuditLogfmt(t, "--parent", "Code")
	if err != nil {
		t.Fatalf("jit audit --parent: %v", err)
	}
	if !strings.Contains(out, "status=decoy") {
		t.Errorf("--parent Code dropped the serve Code's process caused, got:\n%s", out)
	}
	if strings.Contains(out, "status=real") {
		t.Errorf("--parent Code leaked a claude-launched serve, got:\n%s", out)
	}
}

// A carried-over reader identity is an inference (identifyReader's doctrine:
// the scan is rate-limited and races a fast-closing reader). Neither view may
// present it as certainty.
func TestAuditMarksAnInferredReaderAsLikely(t *testing.T) {
	e := authEntry("/Users/alice", agent.SessionEvent{
		UnixTime: 6000, Kind: agent.KindServe, Op: agent.OpServeDecoy,
		By: "/usr/local/bin/node", ByPID: 999, ByLikely: true, Labels: []string{"gcp"},
	})
	if !strings.Contains(e.subject, "likely") {
		t.Errorf("report subject = %q, want it to mark the identity as an inference", e.subject)
	}
	if !strings.Contains(e.match, "reader_likely=true") {
		t.Errorf("logfmt line = %q, want reader_likely=true", e.match)
	}
}

// A fast-closing reader legitimately evades the scan, so "we don't know" is a
// normal outcome and must read as an admission rather than as a name.
func TestAuditServeWithoutAnIdentifiedReader(t *testing.T) {
	e := authEntry("/Users/alice", agent.SessionEvent{
		UnixTime: 6000, Kind: agent.KindServe, Op: agent.OpServeDecoy, Labels: []string{"gcp"},
	})
	if !strings.Contains(e.subject, "unidentified") {
		t.Errorf("report subject = %q, want it to admit the reader wasn't identified", e.subject)
	}
	if strings.Contains(e.match, "reader=") {
		t.Errorf("logfmt line claimed a reader it never had: %q", e.match)
	}
}

// The header counts decoy ROWS, not the collapsed count each row carries: one
// looping watcher would otherwise report thousands and read like a breach.
func TestAuditHeaderCountsDecoyRowsNotReads(t *testing.T) {
	var buf bytes.Buffer
	entries := []auditEntry{
		{t: time.Unix(5000, 0), kind: "serve", status: "decoy", subject: "decoy served to node ×34"},
		{t: time.Unix(4000, 0), kind: "serve", status: "real", subject: "real value served to terraform"},
	}
	writeAuditHeader(&buf, entries)
	if got := buf.String(); !strings.Contains(got, "1 decoy read") {
		t.Errorf("header = %q, want it to count 1 decoy row (not 34 reads)", got)
	}
}

// TestCommandEntrySurfacesFreshAuth: a command that forced its own fresh
// Touch ID/passcode (jit migrate undo/remove set Record.Auth) must show that
// in the audit line, so the trail proves a plaintext-restoring or
// destructive action was gated by a live fingerprint. A command with no
// fresh auth carries no auth= key.
func TestCommandEntrySurfacesFreshAuth(t *testing.T) {
	withAuth := commandEntry(auditlog.Record{
		UnixNano: 1000, Command: "jit migrate undo", Args: []string{"migrate", "undo", "~/proj/.env"},
		Success: true, Auth: freshUserPresenceMethod,
	})
	if !strings.Contains(withAuth.line, "auth="+freshUserPresenceMethod) {
		t.Errorf("expected the fresh-auth marker in the audit line, got:\n%s", withAuth.line)
	}

	noAuth := commandEntry(auditlog.Record{
		UnixNano: 1000, Command: "jit status", Args: []string{"status"}, Success: true,
	})
	if strings.Contains(noAuth.line, "auth=") {
		t.Errorf("expected no auth= key for a command that didn't force a challenge, got:\n%s", noAuth.line)
	}
}

// execAuditLogfmt runs the command in its machine form. The tests that assert
// key=value tokens are testing the logfmt stream's CONTENT — that both sources
// merge, that every filter narrows what it claims to — and that stream is now
// one flag away rather than the default. Naming the format keeps those tests
// pointed at the thing they were written to check; the default report has its
// own tests in auditreport_test.go.
func execAuditLogfmt(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return execAudit(t, append([]string{"--format", "logfmt"}, args...)...)
}

func execAudit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// The audit flags are package-level vars cobra only overwrites when the
	// flag is passed, so reset every one to its default here or a filter from
	// one test leaks into the next.
	auditFormat = "text"
	auditLimit = 50
	auditFollow = false
	auditKinds = nil
	auditSince, auditUntil = "", ""
	auditStatus, auditUser, auditParent, auditSecret, auditGrep = "", "", "", "", ""
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"audit"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestAuditCommandTextMergesCommandsAndAuth(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAuditLogfmt(t)
	if err != nil {
		t.Fatalf("jit audit: %v", err)
	}

	if !strings.Contains(out, `cmd="jit vault get stripe/live-key"`) {
		t.Errorf("command invocation not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "kind=cmd status=ok") || !strings.Contains(out, "user=alice") {
		t.Errorf("command line/actor not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "kind=unlock") || !strings.Contains(out, "method=touchid-or-passcode") {
		t.Errorf("auth event / method not shown, got:\n%s", out)
	}
	if !strings.Contains(out, "secrets=stripe/live-key") {
		t.Errorf("auth labels not shown, got:\n%s", out)
	}
	// The auth event (unix 2000) is newer than the command (unix nano 1000, ~epoch),
	// so its unlock line must sort ahead of the command line.
	if strings.Index(out, "kind=unlock") > strings.Index(out, "kind=cmd") {
		t.Errorf("entries not sorted newest-first, got:\n%s", out)
	}
}

func TestAuditRecorderSkipsNonRunnableParent(t *testing.T) {
	home := withFixtureHome(t)
	// A bare `jit service` resolves to the `service` command GROUP, which
	// prints its help and returns nil. Nothing ran against the user's
	// secrets, so nothing belongs in the durable log — the same treatment a
	// genuinely non-runnable command gets. The group carries a RunE (so a
	// mistyped subcommand can be rejected; see runCommandGroup), which is
	// why the recorder can't just test Runnable() any more.
	recordAuditEvent(serviceCmd, nil, 0)

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if recs := auditlog.New(root, nil).Load(0); len(recs) != 0 {
		t.Errorf("bare command group was recorded, want none: %+v", recs)
	}
}

// TestAuditRecorderRecordsMistypedSubcommand is the other half of the rule
// above, and the reason it isn't simply "skip every group": `jit service
// consnt off` used to print help and exit 0, which meant a script could
// believe it had turned per-process consent off while it stayed on, with
// nothing in the audit log to show for it. That invocation now fails, and a
// failed invocation is exactly what the log exists to carry.
func TestAuditRecorderRecordsMistypedSubcommand(t *testing.T) {
	home := withFixtureHome(t)
	recordAuditEvent(serviceCmd, unknownCommandError(serviceCmd, "consnt"), 0)

	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	recs := auditlog.New(root, nil).Load(0)
	if len(recs) != 1 {
		t.Fatalf("mistyped subcommand not recorded, want 1 record: %+v", recs)
	}
	if recs[0].Success {
		t.Errorf("mistyped subcommand recorded as successful, want failed: %+v", recs[0])
	}
}

func TestAuditCommandJSONShape(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAudit(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit audit --format json: %v", err)
	}
	var got auditJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(got.Commands) != 1 || got.Commands[0].Command != "jit vault get" {
		t.Errorf("commands array wrong: %+v", got.Commands)
	}
	if len(got.AuthEvents) != 1 || got.AuthEvents[0].AuthMethod != "Touch ID or device passcode" {
		t.Errorf("auth_events array wrong: %+v", got.AuthEvents)
	}
}

func TestAuditCommandEmptyIsFriendly(t *testing.T) {
	withFixtureHome(t) // nothing seeded
	out, err := execAudit(t)
	if err != nil {
		t.Fatalf("jit audit on empty: %v", err)
	}
	if !strings.Contains(out, "No audit log yet") {
		t.Errorf("expected a friendly empty message, got:\n%s", out)
	}
}

func TestAuditCommandRejectsUnknownFormat(t *testing.T) {
	withFixtureHome(t)
	_, err := execAudit(t, "--format", "yaml")
	if err == nil {
		t.Fatal("expected an error for an unrecognized --format value, got nil")
	}
	if !strings.Contains(err.Error(), `unknown --format "yaml"`) {
		t.Errorf("expected the error to name the bad format, got: %v", err)
	}
}

func TestAuditCommandLimitCapsEntries(t *testing.T) {
	home := withFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	l := auditlog.New(root, nil)
	for i := 0; i < 10; i++ {
		l.Append(auditlog.Record{UnixNano: int64(i + 1), Command: "jit status", Args: []string{"status"}, User: "alice", Success: true})
	}

	out, err := execAuditLogfmt(t, "--limit", "3")
	if err != nil {
		t.Fatalf("jit audit --limit: %v", err)
	}
	if n := strings.Count(out, "kind=cmd"); n != 3 {
		t.Errorf("--limit 3 showed %d entries, want 3, got:\n%s", n, out)
	}
}

// seedDeniedAndError adds a refused prompt and a rejected-peer error on top of
// seedAuditFixtures' ok unlock and command, so the filter tests have every kind
// and status to narrow among.
func seedDeniedAndError(t *testing.T, home string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	h := newHistoryLog(root, nil)
	h.append(agent.SessionEvent{
		UnixTime: 3000, Kind: agent.KindDenied, Op: agent.OpUnwrap,
		By: "jit run --profile mcp-jamf", LaunchedBy: "claude",
		Cause: "prompt timed out", AuthMethod: "Touch ID or device passcode",
	})
	h.append(agent.SessionEvent{
		UnixTime: 4000, Kind: agent.KindError, Op: "reject",
		Cause: "rejected peer: peer uid 502 != 501", By: "/usr/bin/curl", ByPID: 8080, LaunchedBy: "bash",
	})
}

func TestAuditFilterByKind(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAuditLogfmt(t, "--kind", "unlock")
	if err != nil {
		t.Fatalf("jit audit --kind: %v", err)
	}
	if !strings.Contains(out, "kind=unlock") {
		t.Errorf("--kind unlock dropped the unlock, got:\n%s", out)
	}
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--kind unlock leaked a command line, got:\n%s", out)
	}
}

func TestAuditFilterByStatusDenied(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	seedDeniedAndError(t, home)

	out, err := execAuditLogfmt(t, "--status", "denied")
	if err != nil {
		t.Fatalf("jit audit --status: %v", err)
	}
	if !strings.Contains(out, "status=denied") {
		t.Errorf("--status denied dropped the denial, got:\n%s", out)
	}
	if strings.Contains(out, "status=ok") || strings.Contains(out, "kind=cmd") {
		t.Errorf("--status denied leaked non-denied entries, got:\n%s", out)
	}
}

func TestAuditFilterBySecret(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAuditLogfmt(t, "--secret", "stripe")
	if err != nil {
		t.Fatalf("jit audit --secret: %v", err)
	}
	if !strings.Contains(out, "secrets=stripe/live-key") {
		t.Errorf("--secret stripe dropped the touching unlock, got:\n%s", out)
	}
	// A command record carries no labels, so a secret filter must exclude it.
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--secret leaked a command with no secret labels, got:\n%s", out)
	}
}

func TestAuditFilterByParent(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	seedDeniedAndError(t, home)

	// Only the error event was launched by bash; the rest are claude.
	out, err := execAuditLogfmt(t, "--parent", "bash")
	if err != nil {
		t.Fatalf("jit audit --parent: %v", err)
	}
	if !strings.Contains(out, "kind=error") {
		t.Errorf("--parent bash dropped the bash-launched error, got:\n%s", out)
	}
	if strings.Contains(out, "kind=unlock") || strings.Contains(out, "kind=cmd") {
		t.Errorf("--parent bash leaked claude-launched entries, got:\n%s", out)
	}
}

func TestAuditFilterByGrep(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	out, err := execAuditLogfmt(t, "--grep", "method=touchid")
	if err != nil {
		t.Fatalf("jit audit --grep: %v", err)
	}
	if !strings.Contains(out, "kind=unlock") {
		t.Errorf("--grep matched the unlock's method but dropped it, got:\n%s", out)
	}
	if strings.Contains(out, "kind=cmd") {
		t.Errorf("--grep leaked a line that doesn't match, got:\n%s", out)
	}
}

// A rejected peer is the socket event most worth a durable line; it must render
// as a kind=error line naming what was refused and who the peer was.
func TestAuditRendersRejectedPeer(t *testing.T) {
	home := withFixtureHome(t)
	seedDeniedAndError(t, home)

	out, err := execAuditLogfmt(t)
	if err != nil {
		t.Fatalf("jit audit: %v", err)
	}
	for _, want := range []string{"kind=error", "op=reject", `reason="rejected peer: peer uid 502 != 501"`, "parent=bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("rejected-peer line missing %q, got:\n%s", want, out)
		}
	}
}

func TestAuditRejectsBadFilters(t *testing.T) {
	withFixtureHome(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--kind", "bogus"}, "unknown --kind"},
		{[]string{"--status", "maybe"}, "unknown --status"},
		{[]string{"--since", "yesterday"}, "--since"},
		{[]string{"--grep", "("}, "--grep"},
		{[]string{"--follow", "--format", "json"}, "--follow"},
	}
	for _, c := range cases {
		if _, err := execAudit(t, c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("audit %v: want error containing %q, got %v", c.args, c.want, err)
		}
	}
}

func TestAuditEmptyMatchIsDistinctFromEmptyLog(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)

	// There are entries, just none of this kind: the message must say "no
	// match", not "no log yet", or a filter reads as an empty machine.
	out, err := execAudit(t, "--kind", "lock")
	if err != nil {
		t.Fatalf("jit audit --kind lock: %v", err)
	}
	if !strings.Contains(out, "No audit entries match") {
		t.Errorf("a filter that matches nothing must say so, got:\n%s", out)
	}
}

func TestParseAuditTime(t *testing.T) {
	for _, ok := range []string{"3d", "90m", "2h", "1w", "2026-07-23", "2026-07-23 09:00", "2026-07-23 09:00:05"} {
		if _, err := parseAuditTime(ok); err != nil {
			t.Errorf("parseAuditTime(%q) errored: %v", ok, err)
		}
	}
	if _, err := parseAuditTime("sometime"); err == nil {
		t.Error("parseAuditTime accepted a non-time string")
	}
	// A relative age resolves to that long ago, not a forward offset.
	got, err := parseAuditTime("1h")
	if err != nil {
		t.Fatalf("parseAuditTime(1h): %v", err)
	}
	if d := time.Since(got); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("parseAuditTime(1h) resolved to %v ago, want ~1h", d)
	}
}

// keep's time bounds are the one predicate a wall-clock test pins directly,
// since the fixture timestamps are fixed at epoch and can't exercise "since".
func TestAuditFilterKeepsWithinTimeWindow(t *testing.T) {
	since, _ := parseAuditTime("30m")
	f := auditFilter{since: since}
	now := time.Now()
	if f.keep(auditEntry{t: now.Add(-2 * time.Hour)}) {
		t.Error("an entry older than --since must be dropped")
	}
	if !f.keep(auditEntry{t: now.Add(-time.Minute)}) {
		t.Error("an entry inside the window must be kept")
	}
}

// readNewEvents is the heart of --follow: each poll must return only the lines
// appended since the last offset, and nothing when the file is unchanged.
func TestReadNewEventsIsIncremental(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, historyFileName)
	h := newHistoryLog(dir, nil)

	h.append(agent.SessionEvent{UnixTime: 1, Kind: agent.KindUnlock})
	off, first := readNewEvents(path, 0)
	if len(first) != 1 || first[0].Kind != agent.KindUnlock {
		t.Fatalf("first read = %+v, want the one unlock", first)
	}

	h.append(agent.SessionEvent{UnixTime: 2, Kind: agent.KindLock})
	off2, second := readNewEvents(path, off)
	if len(second) != 1 || second[0].Kind != agent.KindLock {
		t.Fatalf("second read = %+v, want only the new lock", second)
	}

	if _, none := readNewEvents(path, off2); len(none) != 0 {
		t.Errorf("an unchanged file returned %d events, want 0", len(none))
	}
}

// With an already-cancelled context, follow must still print the initial
// matching tail before it returns, so `--follow` on an idle machine shows the
// recent history rather than a blank screen.
func TestFollowPrintsInitialTail(t *testing.T) {
	home := withFixtureHome(t)
	seedAuditFixtures(t, home)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Both output shapes, because --follow renders through the same switch
	// the static view does: the report by default, logfmt when asked. A tail
	// that appeared in only one of them would be a blank screen in the other.
	for _, tc := range []struct{ format, want string }{
		{"text", "session unlocked"},
		{"logfmt", "kind=unlock"},
	} {
		auditFormat = tc.format
		var buf bytes.Buffer
		if err := followAuditLog(ctx, &buf, root, auditFilter{}, 50); err != nil {
			t.Fatalf("followAuditLog(%s): %v", tc.format, err)
		}
		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("--format %s printed no initial tail, want %q, got:\n%s", tc.format, tc.want, buf.String())
		}
	}
	auditFormat = "text"
}
