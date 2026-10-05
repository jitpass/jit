// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/vault"
)

// kubelogin (int128/kubelogin, `kubectl oidc-login`) caches each OIDC login
// in ~/.kube/cache/oidc-login/<sha256> in plaintext by default: an ID token
// and a refresh token. It can keep them in the keychain instead, with
// `--token-cache-storage=keyring` (pkg/cmd/tokencache.go). jit cannot seal
// a cache kubelogin writes on every refresh, but it can set that flag: the
// kubeconfig's exec args gain it, and the plaintext cache goes (backed up
// first). The next kubectl call logs in once more and keeps the token in the
// keychain from then on.

// KubeloginCacheDir returns kubelogin's default token cache directory.
func KubeloginCacheDir(home string) string {
	return filepath.Join(home, ".kube", "cache", "oidc-login")
}

const kubeloginKeyringFlag = "--token-cache-storage=keyring"

var kubeloginCacheFile = regexp.MustCompile(`^[0-9a-f]{64}$`)

// kubeloginArgs returns a kubeconfig user's exec args when the exec plugin
// is kubelogin's get-token: `kubectl oidc-login get-token …`, or the
// kubelogin / kubectl-oidc_login binary run directly.
func kubeloginArgs(userMap map[string]interface{}) ([]interface{}, bool) {
	exec, _ := userMap["exec"].(map[string]interface{})
	if exec == nil {
		return nil, false
	}
	command, _ := exec["command"].(string)
	args, _ := exec["args"].([]interface{})
	base := filepath.Base(command)
	var words []string
	for _, a := range args {
		s, _ := a.(string)
		words = append(words, s)
	}
	switch {
	case base == "kubectl" && len(words) > 1 && words[0] == "oidc-login" && words[1] == "get-token":
	case (base == "kubelogin" || base == "kubectl-oidc_login") && len(words) > 0 && words[0] == "get-token":
	default:
		return nil, false
	}
	// Microsoft's AKS kubelogin (Azure/kubelogin) has the same binary name
	// and a get-token of its own, with no --token-cache-storage: adding the
	// flag there breaks kubectl. int128's get-token always names an OIDC
	// issuer, which Azure's never does.
	for _, w := range words {
		if w == "--oidc-issuer-url" || strings.HasPrefix(w, "--oidc-issuer-url=") {
			return args, true
		}
	}
	return nil, false
}

// kubeloginStorage returns the --token-cache-storage value args set, ""
// when they set none (kubelogin's default, disk).
func kubeloginStorage(args []interface{}) string {
	for i, a := range args {
		s, _ := a.(string)
		if v, ok := strings.CutPrefix(s, "--token-cache-storage="); ok {
			return v
		}
		if s == "--token-cache-storage" && i+1 < len(args) {
			v, _ := args[i+1].(string)
			return v
		}
	}
	return ""
}

// DiscoverKubeloginUsers lists the users in ~/.kube/config whose kubelogin
// keeps its tokens on disk: no --token-cache-storage, or =disk. Sorted.
func DiscoverKubeloginUsers(home string) ([]string, error) {
	doc, err := loadKubeconfig(KubeconfigPath(home))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	users, err := kubeconfigUsers(doc)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range users {
		name, _ := u["name"].(string)
		userMap, _ := u["user"].(map[string]interface{})
		if userMap == nil || name == "" {
			continue
		}
		if args, ok := kubeloginArgs(userMap); ok {
			if s := kubeloginStorage(args); s == "" || s == "disk" {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// KubeloginMigration says what ApplyKubeloginKeyring did.
type KubeloginMigration struct {
	Users      []string // kubeconfig users switched to the keychain
	ConfigPath string
	Backup     string   // vault path of ~/.kube/config's backup
	CacheFiles []string // plaintext token files removed (backed up first)
}

// ApplyKubeloginKeyring switches the given kubelogin users to the keychain
// and removes kubelogin's plaintext cache. The kubeconfig and every cache
// file are backed up first, linked, so `jit migrate undo` puts the
// kubeconfig and the cached logins back together.
//
// Every token file in the default cache goes, not only the switched users':
// a file's name is a SHA-256 of the login's parameters, which jit cannot
// recompute. A login another kubeconfig still keeps on disk is the cost: it
// signs in once more on its next use. The plan says so.
func ApplyKubeloginKeyring(v *vault.Vault, home string, userNames []string, tracker *BackupTracker) (KubeloginMigration, error) {
	path := KubeconfigPath(home)
	res := KubeloginMigration{ConfigPath: path}
	if len(userNames) == 0 {
		return res, nil
	}
	doc, err := loadKubeconfig(path)
	if err != nil {
		return res, fmt.Errorf("reading %s: %w", path, err)
	}
	users, err := kubeconfigUsers(doc)
	if err != nil {
		return res, fmt.Errorf("%s: %w", path, err)
	}
	newArgs := map[string][]interface{}{}
	for _, name := range userNames {
		u, ok := findKubeconfigUser(users, name)
		if !ok {
			return res, fmt.Errorf("user %q not found in %s", name, path)
		}
		userMap, _ := u["user"].(map[string]interface{})
		args, ok := kubeloginArgs(userMap)
		if !ok {
			return res, fmt.Errorf("user %q in %s does not run kubelogin", name, path)
		}
		newArgs[name] = withKeyringStorage(args)
	}

	cacheFiles, err := kubeloginCacheFiles(home)
	if err != nil {
		return res, err
	}
	for _, f := range cacheFiles {
		data, err := os.ReadFile(f) // #nosec G304 -- a token file in kubelogin's cache dir, listed by kubeloginCacheFiles
		if err != nil {
			return res, err
		}
		if _, err := storeSecretBackup(v, f, data, backupFlags{restoreWith: append(restorePartners(cacheFiles, f), path)}); err != nil {
			return res, err
		}
	}
	res.Backup, err = tracker.backupOnceLinking(v, path, cacheFiles)
	if err != nil {
		return res, fmt.Errorf("backing up %s: %w", path, err)
	}
	out, err := setKubeconfigExecArgs(path, newArgs)
	if err != nil {
		return res, err
	}
	if err := writeThroughLink(path, out, 0o600); err != nil {
		return res, fmt.Errorf("writing %s: %w", path, err)
	}
	res.Users = userNames
	for _, f := range cacheFiles {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, fmt.Errorf("removing %s (it is backed up; delete it by hand): %w", f, err)
		}
	}
	res.CacheFiles = cacheFiles
	return res, nil
}

// withKeyringStorage returns args with --token-cache-storage set to
// keyring: an existing setting (=disk, or a separate value) is replaced,
// otherwise the flag is appended.
func withKeyringStorage(args []interface{}) []interface{} {
	out := make([]interface{}, 0, len(args)+1)
	for i := 0; i < len(args); i++ {
		s, _ := args[i].(string)
		if strings.HasPrefix(s, "--token-cache-storage=") {
			continue
		}
		if s == "--token-cache-storage" {
			i++ // and its value
			continue
		}
		out = append(out, args[i])
	}
	return append(out, kubeloginKeyringFlag)
}

// kubeloginCacheFiles lists the token files in kubelogin's default cache:
// the hash-named ones, not the .lock files beside them. Sorted.
func kubeloginCacheFiles(home string) ([]string, error) {
	dir := KubeloginCacheDir(home)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && kubeloginCacheFile.MatchString(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// IsKubeloginCacheFile reports whether path is one of kubelogin's token
// files in its default cache.
func IsKubeloginCacheFile(home, path string) bool {
	return filepath.Dir(path) == KubeloginCacheDir(home) && kubeloginCacheFile.MatchString(filepath.Base(path))
}

// setKubeconfigExecArgs rewrites the exec args of the named users in the
// kubeconfig at path, through the YAML node tree rather than a map, so every
// other key keeps its order and every comment stays (release QA: the map
// round-trip reordered the whole file and dropped comments). The encoder
// does re-indent, at kubectl's two spaces.
func setKubeconfigExecArgs(path string, args map[string][]interface{}) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the fixed ~/.kube/config path
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	users := mappingValue(root.Content[0], "users")
	if users == nil || users.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s has no users list", path)
	}
	done := map[string]bool{}
	for _, item := range users.Content {
		name := mappingValue(item, "name")
		if name == nil || args[name.Value] == nil {
			continue
		}
		seq := mappingValue(mappingValue(mappingValue(item, "user"), "exec"), "args")
		if seq == nil || seq.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("user %q in %s has no exec args", name.Value, path)
		}
		content := make([]*yaml.Node, 0, len(args[name.Value]))
		for _, a := range args[name.Value] {
			if s, ok := a.(string); ok {
				content = append(content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s})
				continue
			}
			// An unquoted 300 or true, which kubectl reads as a string:
			// written back as it was, never blanked (2.4.1 release QA).
			content = append(content, &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprint(a)})
		}
		seq.Content = content
		done[name.Value] = true
	}
	for name := range args {
		if !done[name] {
			return nil, fmt.Errorf("user %q not found in %s", name, path)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mappingValue returns the value node of key in a mapping node, nil when
// node is not a mapping or has no such key.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
