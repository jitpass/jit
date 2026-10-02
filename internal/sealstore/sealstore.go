// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package sealstore

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Layout says which top-level entries of a tool's config dir are secret.
type Layout struct {
	// Secrets are packed into the vault and unpacked for each run.
	Secrets []string
	// Ephemeral entries are a cache the tool rebuilds when missing: never
	// vaulted, never linked, never carried back after a run.
	Ephemeral []string
}

// Gcloud is the layout of a gcloud config dir (SDK 587.0.0, spike E1).
// access_tokens.db holds hour-long access tokens and changes on every
// refresh; gcloud recreates it when absent, so it is ephemeral rather than
// sealed (design D3).
var Gcloud = Layout{
	Secrets:   []string{"credentials.db", "legacy_credentials"},
	Ephemeral: []string{"access_tokens.db"},
}

// Azure is the layout of an Azure CLI config dir (azure-cli 2.90.0,
// spike/azure-cli-store): the MSAL token cache (refresh tokens) and the
// service principal secrets. Everything else, settings and caches alike,
// is written through the run's links (spike E3), so nothing is ephemeral.
var Azure = Layout{
	Secrets: []string{"msal_token_cache.json", "service_principal_entries.json"},
}

// maxBlob bounds what Unpack will extract. A gcloud store is a few KB per
// account; anything near this is not a store this package wrote.
const maxBlob = 64 << 20

func (l Layout) isSecret(name string) bool    { return contains(l.Secrets, name) }
func (l Layout) isEphemeral(name string) bool { return contains(l.Ephemeral, name) }

// isPrivate reports whether a top-level name is either kind of non-setting.
func (l Layout) isPrivate(name string) bool { return l.isSecret(name) || l.isEphemeral(name) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// epoch is every packed entry's time: content, not when it was written,
// decides the bytes.
var epoch = time.Unix(0, 0).UTC()

// entry is one packed file or directory, by its slash path.
type entry struct {
	dir  bool
	mode int64
	data []byte
}

// Pack returns a canonical tar of dir's secret entries. Missing entries are
// skipped, so an empty or logged-out dir packs to an empty archive. Symlinks
// and other non-regular files are refused: the store is files the tool wrote
// itself, and following a link would pack whatever it points at.
func (l Layout) Pack(dir string) ([]byte, error) {
	entries := map[string]entry{}
	if err := l.collect(dir, entries); err != nil {
		return nil, err
	}
	return emit(entries)
}

// Merge returns blob (a Pack result) with dir's secret entries laid over
// it: a file in dir replaces the packed file of the same path, and every
// other packed entry is kept. For folding a login the tool just wrote into
// a store sealed earlier, without unpacking the store anywhere.
func (l Layout) Merge(blob []byte, dir string) ([]byte, error) {
	return l.merge(blob, dir, nil)
}

// MergeFiles is Merge limited to the named files of dir (slash-separated,
// relative to dir) and the directories holding them: for a store taking in
// one login among others the tool keeps in the same directory, which stay
// where they are. A name that is not there is skipped; no names, nothing
// merged.
func (l Layout) MergeFiles(blob []byte, dir string, files []string) ([]byte, error) {
	keep := map[string]bool{}
	for _, f := range files {
		for p := path.Clean(f); p != "." && p != "/"; p = path.Dir(p) {
			keep[p] = true
		}
	}
	return l.merge(blob, dir, keep)
}

// merge lays dir's secret entries over blob; with keep non-nil, only the
// entries it names.
func (l Layout) merge(blob []byte, dir string, keep map[string]bool) ([]byte, error) {
	entries := map[string]entry{}
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading sealed store: %w", err)
		}
		rel, err := l.checkName(hdr.Name)
		if err != nil {
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			entries[rel] = entry{dir: true, mode: hdr.Mode}
		case tar.TypeReg:
			data, err := io.ReadAll(io.LimitReader(tr, maxBlob))
			if err != nil {
				return nil, err
			}
			entries[rel] = entry{mode: hdr.Mode, data: data}
		default:
			return nil, fmt.Errorf("sealed store entry %q: unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
	fresh := map[string]entry{}
	if err := l.collect(dir, fresh); err != nil {
		return nil, err
	}
	for rel, e := range fresh {
		if keep == nil || keep[rel] {
			entries[rel] = e
		}
	}
	return emit(entries)
}

// collect adds dir's secret entries to entries, replacing same paths.
func (l Layout) collect(dir string, entries map[string]entry) error {
	for _, name := range l.Secrets {
		root := filepath.Join(dir, name)
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			info, err := os.Lstat(p)
			if err != nil {
				return err
			}
			switch {
			case info.Mode().IsDir():
				entries[rel] = entry{dir: true, mode: int64(info.Mode().Perm())}
			case info.Mode().IsRegular():
				data, err := readRegularNoFollow(p)
				if err != nil {
					return err
				}
				entries[rel] = entry{mode: int64(info.Mode().Perm()), data: data}
			default:
				return fmt.Errorf("%s: not a regular file or directory", rel)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// readRegularNoFollow reads p only if it is still a regular file when
// opened: O_NOFOLLOW refuses a symlink swapped in after the walk's Lstat,
// and the fstat refuses anything else that took its place (a FIFO would
// block the read). Without it, a link planted between the two calls could
// pack an arbitrary file into the vault.
func readRegularNoFollow(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- p is under dir, built from the layout's own names
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	return io.ReadAll(io.LimitReader(f, maxBlob))
}

// emit writes entries as a canonical tar: sorted paths, fixed times and
// owners, PAX format, so the same content is always the same bytes.
func emit(entries map[string]entry) ([]byte, error) {
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, rel := range paths {
		e := entries[rel]
		hdr := &tar.Header{Name: rel, Mode: e.mode, ModTime: epoch, Format: tar.FormatPAX}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if !e.dir {
			if _, err := tw.Write(e.data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unpack extracts blob (a Pack result) into dir, which must exist. Every
// entry must sit under one of the layout's secret names; files are created
// exclusively, owner-only.
func (l Layout) Unpack(blob []byte, dir string) error {
	if len(blob) > maxBlob {
		return fmt.Errorf("sealed store is %d bytes, over the %d limit", len(blob), maxBlob)
	}
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading sealed store: %w", err)
		}
		rel, err := l.checkName(hdr.Name)
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, filepath.FromSlash(rel))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(dest, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- dest is checkName-confined to dir
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, hdr.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("sealed store entry %q: unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
}

// checkName confines a tar entry to the layout's secret names.
func (l Layout) checkName(name string) (string, error) {
	clean := path.Clean(strings.TrimSuffix(name, "/"))
	if name == "" || path.IsAbs(name) || clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("sealed store entry %q: not a relative path", name)
	}
	top := strings.SplitN(clean, "/", 2)[0]
	if !l.isSecret(top) {
		return "", fmt.Errorf("sealed store entry %q: outside the store", name)
	}
	return clean, nil
}

// Files returns a store's regular files by path: for a store merged in
// memory (migrate.MergeAzureStore) rather than unpacked anywhere.
func Files(blob []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading sealed store: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxBlob))
		if err != nil {
			return nil, err
		}
		out[hdr.Name] = data
	}
}

// PackFiles returns the canonical tar of top-level files, owner-only: the
// store Pack makes of a dir holding them, for one built in memory.
func PackFiles(files map[string][]byte) ([]byte, error) {
	entries := map[string]entry{}
	for name, data := range files {
		if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
			return nil, fmt.Errorf("sealed store entry %q: not a top-level file", name)
		}
		entries[name] = entry{mode: 0o600, data: data}
	}
	return emit(entries)
}

// Empty reports whether blob holds no entries (a logged-out store).
func Empty(blob []byte) bool {
	_, err := tar.NewReader(bytes.NewReader(blob)).Next()
	return errors.Is(err, io.EOF)
}

// Plaintext lists the secret and ephemeral entries present in dir: what a
// sealed config dir must not hold. An absent dir holds none.
func (l Layout) Plaintext(dir string) ([]string, error) {
	var found []string
	for _, name := range append(append([]string{}, l.Secrets...), l.Ephemeral...) {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			found = append(found, name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return found, nil
}

// Remove deletes dir's secret and ephemeral entries — the last step of
// sealing, after the caller has vaulted and backed up the bytes.
func (l Layout) Remove(dir string) error {
	for _, name := range append(append([]string{}, l.Secrets...), l.Ephemeral...) {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// Link fills runDir with a symlink to every settings entry of real, so the
// tool reads the user's configurations and its writes land in real (E2).
// real is created (0755, gcloud's own default) when missing, so a first
// run's settings have somewhere to go.
func (l Layout) Link(real, runDir string) error {
	if err := os.MkdirAll(real, 0o755); err != nil { // #nosec G301 -- gcloud's own mode for its settings dir; no secret lives there
		return err
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if l.isPrivate(e.Name()) {
			continue
		}
		if err := os.Symlink(filepath.Join(real, e.Name()), filepath.Join(runDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Adopt carries the settings a run created or replaced back into real: any
// top-level entry of runDir that is not private and not one of Link's
// symlinks. A file the tool rewrote by rename (replacing the symlink) wins
// over real's copy; a new directory moves only if real has none. Secrets
// and ephemeral entries never move. It returns the names it moved, and
// keeps going past an entry it cannot move: losing a stamp file must not
// cost the store its reseal.
func (l Layout) Adopt(runDir, real string) (moved []string, err error) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if l.isPrivate(name) || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		src, dst := filepath.Join(runDir, name), filepath.Join(real, name)
		if e.IsDir() {
			if _, err := os.Lstat(dst); err == nil {
				continue
			}
		}
		if err := os.Rename(src, dst); err != nil {
			errs = append(errs, err)
			continue
		}
		moved = append(moved, name)
	}
	return moved, errors.Join(errs...)
}
