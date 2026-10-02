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

// Pack returns a canonical tar of dir's secret entries. Missing entries are
// skipped, so an empty or logged-out dir packs to an empty archive. Symlinks
// and other non-regular files are refused: the store is files the tool wrote
// itself, and following a link would pack whatever it points at.
func (l Layout) Pack(dir string) ([]byte, error) {
	var paths []string
	for _, name := range l.Secrets {
		root := filepath.Join(dir, name)
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			paths = append(paths, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, rel := range paths {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{
			Name:    rel,
			Mode:    int64(info.Mode().Perm()),
			ModTime: epoch,
			Format:  tar.FormatPAX,
		}
		switch {
		case info.Mode().IsDir():
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
		case info.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
		default:
			return nil, fmt.Errorf("%s: not a regular file or directory", rel)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg {
			f, err := os.Open(p) // #nosec G304 -- p is under dir, built from the layout's own names
			if err != nil {
				return nil, err
			}
			_, err = io.Copy(tw, f)
			_ = f.Close()
			if err != nil {
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
