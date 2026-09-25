// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealedFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), SealedFile)
	blob := []byte{1, 2, 3, 250}
	if err := writeSealed(path, "tag.TEST-ONLY", blob); err != nil {
		t.Fatal(err)
	}
	k, got, err := readSealed(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) || k.Tag != "tag.TEST-ONLY" || k.Wrap != wrapECIES || k.Version != sealedVersion {
		t.Fatalf("read back %+v %x", k, got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode %o, want 600", perm)
	}
}

func TestSealedFileMissingIsNotExist(t *testing.T) {
	_, _, err := readSealed(filepath.Join(t.TempDir(), SealedFile))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want fs.ErrNotExist", err)
	}
}

// A file this build does not understand is refused with a sentence, never
// guessed at: the same rule the grant ledger's unknown "wrap" follows.
func TestSealedFileRefusesWhatItCannotRead(t *testing.T) {
	good := sealedKey{Version: sealedVersion, Wrap: wrapECIES, Tag: "t", Blob: "0102"}
	cases := map[string]func(k *sealedKey) string{
		"newer version": func(k *sealedKey) string { k.Version = 2; return "update jit" },
		"unknown wrap":  func(k *sealedKey) string { k.Wrap = "se-p256-v9"; return "cannot open" },
		"bad hex":       func(k *sealedKey) string { k.Blob = "zz"; return "damaged" },
		"empty blob":    func(k *sealedKey) string { k.Blob = ""; return "damaged" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			k := good
			want := mutate(&k)
			data, _ := json.Marshal(k)
			path := filepath.Join(t.TempDir(), SealedFile)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readSealed(path); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want an error containing %q", err, want)
			}
		})
	}
	t.Run("not json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), SealedFile)
		if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readSealed(path); err == nil {
			t.Fatal("garbage accepted")
		}
	})
}

func TestWriteSealedRefusesEmpty(t *testing.T) {
	if err := writeSealed(filepath.Join(t.TempDir(), SealedFile), "t", nil); err == nil {
		t.Fatal("wrote an empty sealed key")
	}
}
