// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"

	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// AzureStorePath is where the Azure CLI's login store lives in the vault:
// one canonical tar of msal_token_cache.json and
// service_principal_entries.json (sealstore.Azure), class azure
// (design/azure-sealed-store.md).
const AzureStorePath = "azure-cli/store"

// AzureStore is the Azure CLI's login store. Its refresh token rotates on
// every refresh (spike/azure-cli-store E2) and az commands run long and in
// parallel, so a run's changes are merged into the vault's copy, entry by
// entry (MergeAzureStore), and no backup is taken per reseal: undo and
// Remove JitPass write back the vault's current copy.
var AzureStore = ToolStore{
	Name:       "az",
	Tool:       "Azure CLI",
	Label:      "the Azure CLI's login",
	VaultPath:  AzureStorePath,
	Class:      vault.ClassAzure,
	Layout:     sealstore.Azure,
	ConfigDir:  AzureConfigDir,
	ConfigEnv:  "AZURE_CONFIG_DIR",
	Provenance: "msal_token_cache.json",
	DirMode:    0o700,
	Rotates:    true,
	Merge:      MergeAzureStore,
}

// AzureConfigDir is the Azure CLI config dir jit seals: the default one.
// An AZURE_CONFIG_DIR pointing elsewhere is left alone.
func AzureConfigDir(home string) string { return filepath.Join(home, ".azure") }

// MergeAzureStore lays the changes a run made to the Azure CLI's store
// (after, against the base it started from) over current, the vault's copy
// another run has sealed since. Both files are collections of entries:
// the MSAL token cache is {section: {key: entry}}, the service principal
// store a list keyed by client and tenant. An entry the run added,
// changed or removed is taken from the run; every other entry is current's,
// so neither run's login or rotated token is lost. A file that is not
// that shape is taken whole from the run, as an unmerged reseal would.
func MergeAzureStore(base, current, after []byte) ([]byte, error) {
	var stores [3]map[string][]byte
	for i, blob := range [][]byte{base, current, after} {
		files, err := sealstore.Files(blob)
		if err != nil {
			return nil, err
		}
		stores[i] = files
	}
	b, c, a := stores[0], stores[1], stores[2]
	out := map[string][]byte{}
	for name := range union(b, c, a) {
		var merged []byte
		var err error
		switch name {
		case "msal_token_cache.json":
			merged, err = mergeMSALCache(b[name], c[name], a[name])
		case "service_principal_entries.json":
			merged, err = mergeSPEntries(b[name], c[name], a[name])
		default:
			err = errUnmergeable
		}
		if errors.Is(err, errUnmergeable) {
			merged, err = a[name], nil
		}
		if err != nil {
			return nil, err
		}
		if merged != nil {
			out[name] = merged
		}
	}
	return sealstore.PackFiles(out)
}

var errUnmergeable = errors.New("not a store this merge understands")

// mergeMSALCache merges MSAL token caches by (section, key). A cache with
// no entry left is no file at all, as az leaves it after a sign-out.
func mergeMSALCache(base, current, after []byte) ([]byte, error) {
	var maps [3]map[string]map[string]json.RawMessage
	for i, data := range [][]byte{base, current, after} {
		maps[i] = map[string]map[string]json.RawMessage{}
		if len(data) > 0 && json.Unmarshal(data, &maps[i]) != nil {
			return nil, errUnmergeable
		}
	}
	b, out, a := maps[0], maps[1], maps[2]
	for section := range union(b, a) {
		for key := range union(b[section], a[section]) {
			was, wasOK := b[section][key]
			now, nowOK := a[section][key]
			if wasOK == nowOK && bytes.Equal(was, now) {
				continue // the run left it alone: current's stands
			}
			if !nowOK {
				delete(out[section], key)
				continue
			}
			if out[section] == nil {
				out[section] = map[string]json.RawMessage{}
			}
			out[section][key] = now
		}
	}
	for _, entries := range out {
		if len(entries) > 0 {
			return json.Marshal(out)
		}
	}
	return nil, nil
}

// mergeSPEntries merges service principal entries by client and tenant,
// sorted. No entry left is no file.
func mergeSPEntries(base, current, after []byte) ([]byte, error) {
	var maps [3]map[string]json.RawMessage
	for i, data := range [][]byte{base, current, after} {
		var list []json.RawMessage
		if len(data) > 0 && json.Unmarshal(data, &list) != nil {
			return nil, errUnmergeable
		}
		maps[i] = map[string]json.RawMessage{}
		for _, e := range list {
			var id struct {
				ClientID string `json:"client_id"`
				Tenant   string `json:"tenant"`
			}
			if json.Unmarshal(e, &id) != nil {
				return nil, errUnmergeable
			}
			maps[i][id.ClientID+"\x00"+id.Tenant] = e
		}
	}
	b, out, a := maps[0], maps[1], maps[2]
	for key := range union(b, a) {
		was, wasOK := b[key]
		now, nowOK := a[key]
		switch {
		case wasOK == nowOK && bytes.Equal(was, now):
		case nowOK:
			out[key] = now
		default:
			delete(out, key)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	list := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		list = append(list, out[k])
	}
	return json.MarshalIndent(list, "", "    ")
}

// union returns the keys of every map given.
func union[V any](maps ...map[string]V) map[string]bool {
	out := map[string]bool{}
	for _, m := range maps {
		for k := range m {
			out[k] = true
		}
	}
	return out
}
