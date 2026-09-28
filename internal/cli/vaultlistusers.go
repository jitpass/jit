// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"path"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/profile"
)

// vaultListUsers is `jit vault list --users`: every profile anywhere that
// names a secret, not only the current folder's and the global store's.
var vaultListUsers bool

// vaultSecretUser is one thing using a secret, as `--users` lists it: a
// profile, with the project folder it lives in (empty for the global
// store), or a pointer file.
type vaultSecretUser struct {
	Profile     string `json:"profile,omitempty"`
	Project     string `json:"project,omitempty"`
	PointerFile string `json:"pointer_file,omitempty"`
}

// discoverSecretUsers is the discovery `jit vault orphans` makes
// (launchers.Discover: project stores anywhere under home, the mount
// registry, pointer files), for DISPLAY: a source that fails to read is
// skipped, never an error, because a listing must not fail over a profile
// it only annotates. It costs a walk (about 0.5s on a real Mac, against
// 0.04s for the listing), so it runs only when asked. Nothing that deletes
// uses it; those go through collectVaultUsers, which is strict.
func discoverSecretUsers(root, cwd string) map[string][]vaultSecretUser {
	home, err := profile.GlobalRoot()
	if err != nil {
		return nil
	}
	m, err := launchers.Discover(launchers.Options{Home: home, Root: root, Cwd: cwd})
	if err != nil || m == nil {
		return nil
	}
	out := map[string][]vaultSecretUser{}
	for vaultPath, uses := range vaultUsageFromMap(m).byPath {
		for _, u := range uses {
			user := vaultSecretUser{Profile: u.ProfileName, PointerFile: u.PointerFile}
			if u.Scope == profile.ScopeProject {
				user.Project = u.Project
			}
			dup := false
			for _, have := range out[vaultPath] {
				if have == user {
					dup = true
					break
				}
			}
			if !dup {
				out[vaultPath] = append(out[vaultPath], user)
			}
		}
	}
	return out
}

// nameLooksSecret is whether the vault path's variable is named like a
// credential (audit.NameSaysCredential): a URL-shaped name is not, since
// only its value can say whether it embeds one.
func nameLooksSecret(vaultPath string) bool {
	return audit.NameSaysCredential(path.Base(vaultPath))
}
