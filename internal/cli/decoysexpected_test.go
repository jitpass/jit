// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jitpass/jit/internal/agent"
)

// An editor indexing a folder read one protected file 1,712 times in two
// minutes (2026-09-28). Marked expected, its decoy reads are tagged so
// JitPass counts them apart; nothing else is.
func TestExpectedReadersTagOnlyTheirOwnDecoyReads(t *testing.T) {
	editor := "/Applications/Some Editor.app/Contents/MacOS/Some Editor"
	list := expectedReaders{Expected: []expectedReader{
		{Program: editor, File: "~/work/billing-sync/.env"},
		{Program: "/usr/bin/backupd"},
	}}
	read := func(by, label, op string) agent.SessionEvent {
		return agent.SessionEvent{Kind: "serve", Op: op, By: by, Labels: []string{label}}
	}
	cases := []struct {
		name string
		ev   agent.SessionEvent
		want bool
	}{
		{"the editor, its file", read(editor, "~/work/billing-sync/.env", "decoy"), true},
		{"the editor with arguments", read(editor+" --type=utility", "~/work/billing-sync/.env", "decoy"), true},
		{"the editor, another file", read(editor, "~/work/reports/.env", "decoy"), false},
		{"a program whose path only starts the same", read(editor+"Helper", "~/work/billing-sync/.env", "decoy"), false},
		{"every file for a whole-Mac mark", read("/usr/bin/backupd -q", "~/work/reports/.env", "decoy"), true},
		{"a real read is never expected", read(editor, "~/work/billing-sync/.env", "real"), false},
		{"another program", read("/usr/bin/python3 sync.py", "~/work/billing-sync/.env", "decoy"), false},
	}
	for _, c := range cases {
		if got := list.isExpected(c.ev); got != c.want {
			t.Errorf("%s: expected = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDecoysExpectAndUnexpectRoundTrip(t *testing.T) {
	withFixtureHome(t)
	t.Cleanup(func() { decoysFormat, decoysFile = "text", "" })
	run := func(args ...string) expectedReaders {
		t.Helper()
		decoysFormat, decoysFile = "text", ""
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs(append(args, "--format", "json"))
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("jit %v: %v\n%s", args, err, buf.String())
		}
		var list expectedReaders
		if err := json.Unmarshal(buf.Bytes(), &list); err != nil {
			t.Fatalf("parsing: %v\n%s", err, buf.String())
		}
		return list
	}
	if got := run("decoys", "expected"); len(got.Expected) != 0 {
		t.Fatalf("a fresh list: %+v", got)
	}
	got := run("decoys", "expect", "/usr/bin/editor", "--file", "~/work/app/.env")
	if len(got.Expected) != 1 || got.Expected[0].File != "~/work/app/.env" || got.Expected[0].SinceUnix == 0 {
		t.Fatalf("after expect: %+v", got)
	}
	if again := run("decoys", "expect", "/usr/bin/editor", "--file", "~/work/app/.env"); len(again.Expected) != 1 {
		t.Fatalf("marking twice keeps one: %+v", again)
	}
	run("decoys", "expect", "/usr/bin/editor")
	if got := run("decoys", "unexpect", "/usr/bin/editor", "--file", "~/work/app/.env"); len(got.Expected) != 1 || got.Expected[0].File != "" {
		t.Fatalf("unexpect one file keeps the whole-Mac mark: %+v", got)
	}
	if got := run("decoys", "unexpect", "/usr/bin/editor"); len(got.Expected) != 0 {
		t.Fatalf("unexpect with no file removes every mark: %+v", got)
	}
}
