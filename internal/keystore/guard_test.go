// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keystore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNothingElseBuildsAKeychainWrapper is the seam's guard: outside
// internal/keychainwrap (which is the backend) and this package (which
// chooses it), no production code calls keychainwrap.New(). A call anywhere
// else is a place that would keep using the keychain after a vault moved to
// the Secure Enclave, which is exactly the bug this package exists to
// prevent. Tests are exempt: they build what they stub.
func TestNothingElseBuildsAKeychainWrapper(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch filepath.Base(path) {
				case "keychainwrap", "keystore", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "New" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "keychainwrap" {
					offenders = append(offenders, fset.Position(call.Pos()).String())
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range offenders {
		t.Errorf("%s: keychainwrap.New() outside internal/keystore; use keystore.Open(root)", o)
	}
}
