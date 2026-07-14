// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"gopkg.in/yaml.v3"
)

// extractYAML walks a YAML mapping tree along the selector's segments and
// returns the scalar at the end. Only mappings are descended — a selector
// segment never indexes into a sequence, because no cataloged file needs
// it, and guessing at sequence semantics here would let a wrong selector
// silently match the wrong entry.
func extractYAML(data []byte, selector string) (string, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return "", false
	}
	node := doc.Content[0]
	for _, part := range selectorParts(selector) {
		next, ok := yamlMapValue(node, part)
		if !ok {
			return "", false
		}
		node = next
	}
	if node.Kind != yaml.ScalarNode || node.Value == "" {
		return "", false
	}
	return node.Value, true
}

// yamlMapValue returns the value node for key inside a mapping node.
func yamlMapValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1], true
		}
	}
	return nil, false
}
