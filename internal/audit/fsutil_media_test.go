// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"testing"
)

// A whole-home walk must not enter Apple's media libraries: they hold no
// secret, they dominate the file count, and on macOS reading them is what
// triggers the Photos and Apple Music privacy prompts for whichever app
// ran the scan.
func TestSkipNoiseDirSkipsMediaLibraries(t *testing.T) {
	root := t.TempDir()
	skipped := []string{
		filepath.Join(root, "Pictures", "Photos Library.photoslibrary"),
		filepath.Join(root, "Anywhere", "Old.photoslibrary"),
		filepath.Join(root, "Music", "Music"),
		filepath.Join(root, "Movies", "TV"),
		filepath.Join(root, "Movies", "Holiday.imovielibrary"),
	}
	for _, dir := range skipped {
		if !SkipNoiseDir(root, dir, filepath.Base(dir)) {
			t.Errorf("SkipNoiseDir(%q) = false, want true", dir)
		}
	}
	walked := []string{
		filepath.Join(root, "Pictures"),
		filepath.Join(root, "Music"),
		filepath.Join(root, "Music", "Projects"),
		filepath.Join(root, "Movies"),
	}
	for _, dir := range walked {
		if SkipNoiseDir(root, dir, filepath.Base(dir)) {
			t.Errorf("SkipNoiseDir(%q) = true, want false: only the library package is noise", dir)
		}
	}
}
