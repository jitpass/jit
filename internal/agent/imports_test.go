// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"go/build"
	"sort"
	"strings"
	"testing"
)

// The agent never imports internal/vault, directly or through another jit
// package (doc.go, client.go, server.go's OnResolveGrant, job.go): the CLI's
// wiring reads the vault and hands the agent wrapped bytes. The durable
// state-file write it shares with the vault lives in internal/atomicfile, a
// leaf both import, for that reason. Walks this package's non-test imports
// with go/build, the graph `go list -deps` prints.
func TestAgentNeverDependsOnTheVault(t *testing.T) {
	const module = "github.com/jitpass/jit/"
	forbidden := module + "internal/vault"
	seen := map[string][]string{} // package -> the chain that reached it
	var walk func(path string, chain []string)
	walk = func(path string, chain []string) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = chain
		pkg, err := build.Default.Import(path, ".", 0)
		if err != nil {
			t.Fatalf("importing %s: %v", path, err)
		}
		for _, imp := range pkg.Imports {
			if strings.HasPrefix(imp, module) {
				walk(imp, append(append([]string{}, chain...), imp))
			}
		}
	}
	walk(module+"internal/agent", []string{module + "internal/agent"})
	if chain, ok := seen[forbidden]; ok {
		t.Fatalf("internal/agent depends on internal/vault: %s", strings.Join(chain, " -> "))
	}
	var deps []string
	for p := range seen {
		deps = append(deps, p)
	}
	sort.Strings(deps)
	if len(deps) < 2 {
		t.Fatalf("the walk found no jit imports at all (%v): it is not walking", deps)
	}
}
