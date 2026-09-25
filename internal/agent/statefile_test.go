// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// calls lists every package-qualified call ("os.Rename", "s.writeState") in
// the named function of a file in this package.
func calls(t *testing.T, file, fn string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok {
						out = append(out, id.Name+"."+sel.Sel.Name)
					}
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("%s has no func %s", file, fn)
	}
	return out
}

// The ledger and the job list are written durably: a move (plan C3) deletes
// a grant's old key right after the file names the new one, so a write that
// a power cut could undo would leave a grant naming a deleted key. The
// ledger once wrote its own temp and renamed it with no fsync of the file or
// the directory; both now go through writeState, which is
// atomicfile.WriteFile (vault.AtomicWriteFile's one implementation).
func TestStateFilesAreWrittenDurably(t *testing.T) {
	for _, c := range []struct{ file, fn string }{
		{"standing.go", "saveLedger"},
		{"job.go", "saveJobsLocked"},
	} {
		got := calls(t, c.file, c.fn)
		through := false
		for _, call := range got {
			if strings.HasPrefix(call, "os.") && call != "os.ErrNotExist" {
				t.Errorf("%s writes with %s itself; it must go through writeState", c.fn, call)
			}
			through = through || call == "s.writeState"
		}
		if !through {
			t.Errorf("%s does not write through writeState (calls %v)", c.fn, got)
		}
	}
	w := calls(t, "standing.go", "writeState")
	if !strings.Contains(strings.Join(w, " "), "atomicfile.WriteFile") {
		t.Errorf("writeState does not use atomicfile.WriteFile (calls %v)", w)
	}
}

// What the ledger's own writer promised, kept: mode 0600, and a symlink
// planted where a temp file goes is never written through.
func TestLedgerWriteKeepsItsGuarantees(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "grants.json")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, ledger+".tmp"); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	if _, err := s.SetGrantLedger(ledger); err != nil {
		t.Fatal(err)
	}
	s.standing["g-00000001"] = &standingGrant{id: "g-00000001", anchorPath: "/Applications/Claude.app", name: "node", secrets: map[string]standingSecret{}}
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("ledger is %v, want a regular file, 0600", fi.Mode())
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Errorf("the save wrote through a planted symlink: victim now %q", b)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("a temp file survived the save: %s", e.Name())
		}
	}
}
