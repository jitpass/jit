// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/json"
	"sort"
)

// MCPProfileOwner is one profile an MCP config launches, with the owner
// string the block launching it would record in the profile's .source
// sidecar: the config path, or "path#projectDir" for a server inside one
// of ~/.claude.json's project blocks (mcpSourceScope).
type MCPProfileOwner struct {
	Profile string
	Server  string
	Owner   string
	Layer   int // the wrapper layer, 0 for the outermost
}

// MCPProfileOwners lists, for every wrapped server entry in path, every
// wrapper layer's profile together with its block-scoped owner string. It
// is WrappedMCPEntriesIn with the block kept: `jit profile attach` must
// write the owner migrate itself would have written, and one file can
// launch the same profile from several blocks, each its own owner.
//
// Entries come back in block order (top level first, then projects by
// directory), servers sorted by name within a block, layers outermost
// first. An unreadable or malformed file is an error.
func MCPProfileOwners(path string) ([]MCPProfileOwner, error) {
	_, blocks, _, err := loadMCPFile(path)
	if err != nil {
		return nil, err
	}
	var out []MCPProfileOwner
	for _, b := range blocks {
		owner := mcpSourceScope(path, b.projectDir)
		names := make([]string, 0, len(b.servers))
		for name := range b.servers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			entry := b.servers[name]
			outer := mcpWrapperProfile(entry)
			if outer == "" {
				continue
			}
			var command string
			_ = json.Unmarshal(entry["command"], &command) // a malformed command still names its outer profile
			var args []string
			_ = json.Unmarshal(entry["args"], &args) // shape already validated by mcpWrapperProfile
			_, _, layers := unwrapJitWrappers(command, args)
			if len(layers) == 0 {
				layers = []string{outer}
			}
			for i, p := range layers {
				out = append(out, MCPProfileOwner{Profile: p, Server: name, Owner: owner, Layer: i})
			}
		}
	}
	return out, nil
}
