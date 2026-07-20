// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestExtractTokenRefusesLiveMount proves the guard added for gemini/codex
// (extract.go's ExtractToken doc comment): a Source path that is currently
// a FIFO — meaning jit migrate already turned it into a live mount — must
// be refused with an error, never read as if it were the tool's own
// plaintext config. Reading a FIFO with jit's own Serve goroutine behind
// it doesn't block or fail; it silently returns whatever cycle is being
// served (decoys by default), which would otherwise get vaulted as the
// "real" token.
func TestExtractTokenRefusesLiveMount(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".gemini")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".env")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("creating test FIFO: %v", err)
	}

	src := TokenSource{Path: "~/.gemini/.env", Format: "toml", Selector: "GEMINI_API_KEY"}
	_, found, err := ExtractToken(home, src)
	if err == nil {
		t.Fatal("expected ExtractToken to refuse a live FIFO mount, got nil error")
	}
	if found {
		t.Error("found=true on a refused FIFO read")
	}
	if !strings.Contains(err.Error(), "live jit mount") {
		t.Errorf("error doesn't explain the refusal: %v", err)
	}
}
