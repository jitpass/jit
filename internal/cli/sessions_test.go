// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/migrate"
)

var sessionNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.Local)

func stampAt(d time.Duration) int64 { return sessionNow.Add(d).Unix() }

func TestSessionsRowStates(t *testing.T) {
	mint := func(app string) string { return "clisso get " + app }
	for _, tc := range []struct {
		name     string
		sessions []statusSession
		want     []string
		absent   []string
	}{
		{"omitted when nothing is a session", nil, nil, []string{"sessions"}},
		{"all live", []statusSession{
			{Profile: "aws-stage", ExpiresUnix: stampAt(9 * time.Hour), Live: true, Mint: mint("stage")},
			{Profile: "aws-dev", ExpiresUnix: stampAt(6 * time.Hour), Live: true, Mint: mint("dev")},
		}, []string{"sessions ● 2 live", "stage expires 2026-09-05 21:00", "dev expires 2026-09-05 18:00"}, []string{"→"}},
		{"one expired names the mint command", []statusSession{
			{Profile: "aws-stage", ExpiresUnix: stampAt(9 * time.Hour), Live: true, Mint: mint("stage")},
			{Profile: "aws-prod", ExpiresUnix: stampAt(-3 * time.Hour), Mint: mint("prod")},
		}, []string{"○ 1 live, 1 expired", "prod expired 3h ago", "→ clisso get prod"}, nil},
		{"all expired, several", []statusSession{
			{Profile: "aws-stage", ExpiresUnix: stampAt(-3 * time.Hour), Mint: mint("stage")},
			{Profile: "aws-prod", ExpiresUnix: stampAt(-30 * time.Hour), Mint: mint("prod")},
		}, []string{"✗ 2 expired", "prod expired 30h ago", "→ clisso get stage, then prod"}, nil},
		{"a pre-stamp capture counts as live and says so", []statusSession{
			{Profile: "aws-dev", Live: true, Mint: mint("dev")},
		}, []string{"● 1 live", "dev expiry unknown until its next login"}, []string{"1970", "→"}},
		{"an expired session no tool claims gets no command", []statusSession{
			{Profile: "aws-ci", Origin: "~/.aws/credentials", ExpiresUnix: stampAt(-time.Hour)},
		}, []string{"✗ 1 expired", "ci expired 1h ago"}, []string{"→"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			printSessionsSection(&buf, tc.sessions, sessionNow)
			// Wrap-insensitive: the assertions are about facts, and the
			// non-breaking joins are an implementation of the layout.
			out := strings.Join(strings.Fields(strings.ReplaceAll(buf.String(), clauseSpace, " ")), " ")
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("row missing %q:\n%s", w, out)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(out, a) {
					t.Errorf("row must not contain %q:\n%s", a, out)
				}
			}
		})
	}
}

func TestSessionsStatusFromReportsLiveAndRemaining(t *testing.T) {
	// stage was born from a ~/.aws/credentials migration and is re-minted
	// by clisso ever after: the app list, not the origin, says it is
	// clisso's.
	got := sessionsStatusFrom([]migrate.Session{
		{Profile: "aws-stage", Origin: "~/.aws/credentials", ExpiresUnix: stampAt(90 * time.Minute)},
		{Profile: "aws-prod", ExpiresUnix: stampAt(-time.Minute)},
		{Profile: "aws-dev"},
	}, map[string]bool{"stage": true}, sessionNow)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if !got[0].Live || got[0].RemainingSeconds != 90*60 || got[0].Mint != "clisso get stage" {
		t.Errorf("stage = %+v, want live with 5400s left and its mint command", got[0])
	}
	if got[1].Mint != "" {
		t.Errorf("prod = %+v, want no mint command for an app clisso does not define", got[1])
	}
	if got[1].Live || got[1].RemainingSeconds != 0 {
		t.Errorf("prod = %+v, want expired with 0 left", got[1])
	}
	if !got[2].Live || got[2].ExpiresUnix != 0 {
		t.Errorf("dev = %+v, want live with unknown expiry", got[2])
	}
}

// The wrapped `clisso status` must be byte-compatible with clisso's own
// table where scripts look (the APP column, the borders, the empty-state
// sentence); only EXPIRE AT departs, from a raw epoch to a date.
func TestClissoStatusTableShape(t *testing.T) {
	var buf bytes.Buffer
	renderClissoStatusTable(&buf, []clissoStatusRow{
		{App: "stage", ExpireAt: "2026-09-05 21:11", Remaining: "9h11m"},
		{App: "dev", ExpireAt: "2026-09-05 18:35", Remaining: "6h35m"},
	})
	want := "" +
		"+-------+------------------+-----------+\n" +
		"|  APP  |    EXPIRE AT     | REMAINING |\n" +
		"+-------+------------------+-----------+\n" +
		"| stage | 2026-09-05 21:11 | 9h11m     |\n" +
		"| dev   | 2026-09-05 18:35 | 6h35m     |\n" +
		"+-------+------------------+-----------+\n"
	if buf.String() != want {
		t.Errorf("table =\n%s\nwant\n%s", buf.String(), want)
	}
	// The line a login function greps.
	if !strings.Contains(buf.String(), "| stage |") {
		t.Error("APP column lost the shape scripts grep for")
	}

	buf.Reset()
	renderClissoStatusTable(&buf, nil)
	if buf.String() != "No apps with valid credentials\n" {
		t.Errorf("empty table = %q, want clisso's own sentence", buf.String())
	}
}

func TestClissoStatusRowsSelectsClissoLiveStamped(t *testing.T) {
	apps := map[string]bool{"stage": true, "prod": true, "dev": true}
	rows := clissoStatusRows([]migrate.Session{
		{Profile: "aws-stage", Origin: "~/.aws/credentials", ExpiresUnix: stampAt(9*time.Hour + 11*time.Minute)}, // clisso's by app, whatever its origin
		{Profile: "aws-prod", ExpiresUnix: stampAt(-time.Hour)},                                                  // expired
		{Profile: "aws-dev"}, // pre-stamp
		{Profile: "aws-ci", ExpiresUnix: stampAt(time.Hour)}, // not an app clisso defines
	}, apps, sessionNow)
	if len(rows) != 1 || rows[0].App != "stage" || rows[0].Remaining != "9h11m" || rows[0].ExpireAt != "2026-09-05 21:11" {
		t.Errorf("rows = %+v, want exactly stage / 2026-09-05 21:11 / 9h11m", rows)
	}
}

func TestRemainingUnits(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                            "0m",
		-time.Hour:                   "0m",
		45 * time.Minute:             "45m",
		9*time.Hour + 11*time.Minute: "9h11m",
		2 * time.Hour:                "2h",
		26 * time.Hour:               "1d2h",
		48 * time.Hour:               "2d",
	} {
		if got := remainingUnits(d); got != want {
			t.Errorf("remainingUnits(%s) = %q, want %q", d, got, want)
		}
	}
}

// status routes to the vault only when it is a plain status: -r is the
// user naming the file, and global flags before the subcommand still
// count (cobra's own parse).
func TestParseClissoArgsStatus(t *testing.T) {
	for _, tc := range []struct {
		args         []string
		sub          string
		explicitRead bool
	}{
		{[]string{"status"}, "status", false},
		{[]string{"--log-level", "warn", "status"}, "status", false},
		{[]string{"status", "-r", "/tmp/creds"}, "status", true},
		{[]string{"status", "--read-from-file=/tmp/creds"}, "status", true},
		{[]string{"-r", "/tmp/creds", "status"}, "status", true},
	} {
		inv := parseClissoArgs(tc.args)
		if inv.sub != tc.sub || inv.explicitRead != tc.explicitRead {
			t.Errorf("parseClissoArgs(%v) = sub %q explicitRead %v, want %q %v", tc.args, inv.sub, inv.explicitRead, tc.sub, tc.explicitRead)
		}
	}
}

// End to end against a real (read-only) vault: a wrapped ~/.clisso.yaml,
// a captured session whose envelope carries the stamp, and `clisso
// status` answered from the vault without ever decrypting — the envelope
// here has a junk payload that could never open, which is the proof.
func TestClissoStatusFromVault(t *testing.T) {
	home := withFixtureHome(t)
	writeClissoConfig := func(body string) {
		if err := os.WriteFile(filepath.Join(home, ".clisso.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeClissoConfig("apps:\n  stage:\n    app-id: \"1\"\n  prod:\n    app-id: \"2\"\nproviders:\n  acme:\n    client-secret: jit://vault/wrap-clisso/acme-client-secret\n")
	wrapped, err := clissoConfigWrapped()
	if err != nil || !wrapped {
		t.Fatalf("clissoConfigWrapped = %v, %v; want true, nil", wrapped, err)
	}

	expires := sessionNow.Add(9*time.Hour + 11*time.Minute).Unix()
	plant := func(profile string, stamp int64) {
		writeVaultEnc(t, home, profile+"/EXPIRATION",
			fmt.Sprintf(`{"version":5,"expires_unix":%d,"origin":"~/.clisso.yaml","recipients":{"test":"00"},"payload":"00"}`, stamp))
		dir := filepath.Join(home, ".jit", "profiles")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := fmt.Sprintf("ACCESS_KEY_ID: %s/ACCESS_KEY_ID\nEXPIRATION: %s/EXPIRATION\n", profile, profile)
		if err := os.WriteFile(filepath.Join(dir, profile+".yaml"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plant("aws-stage", expires)
	plant("aws-prod", sessionNow.Add(-time.Hour).Unix()) // expired: not listed
	plant("aws-other", expires)                          // not an app clisso defines: not listed

	var stdout, stderr bytes.Buffer
	if err := runClissoStatus(&stdout, &stderr, sessionNow); err != nil {
		t.Fatalf("runClissoStatus: %v", err)
	}
	if !strings.Contains(stdout.String(), "| stage | "+sessionClock(expires)+" | 9h11m     |") {
		t.Errorf("stdout = %q, want the stage row with its date", stdout.String())
	}
	for _, absent := range []string{"prod", "other"} {
		if strings.Contains(stdout.String(), absent) {
			t.Errorf("stdout lists %q, which must not appear:\n%s", absent, stdout.String())
		}
	}
	if !strings.HasPrefix(stderr.String(), "jit: answered from the vault") {
		t.Errorf("stderr = %q, want jit's attribution line", stderr.String())
	}

	// A config with no pointer is not the wrap's: clisso's own status
	// must answer, so the shim must not intercept.
	writeClissoConfig("apps:\n  stage:\n    app-id: \"1\"\nproviders:\n  acme:\n    client-secret: plaintext\n")
	if wrapped, err := clissoConfigWrapped(); err != nil || wrapped {
		t.Errorf("clissoConfigWrapped on an unwrapped config = %v, %v; want false, nil", wrapped, err)
	}
}
