// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package lineage

import (
	"os"
	"testing"
)

func TestAncestryNamedUnderPath(t *testing.T) {
	self := int32(os.Getpid())    // #nosec G115 -- test pid
	parent := int32(os.Getppid()) // #nosec G115 -- test ppid
	me, ok := Describe(self)
	if !ok || me.Name() == "" {
		t.Fatal("Describe(self) yields no name")
	}
	up, ok := Describe(parent)
	if !ok || up.ExecPath == "" {
		t.Fatal("Describe(parent) yields no exec path")
	}

	if !AncestryNamedUnderPath(self, up.ExecPath, me.Name()) {
		t.Errorf("self (%s) under its parent's executable %s: false, want true", me.Name(), up.ExecPath)
	}
	// Negative controls: another app, another name, and launchd.
	if AncestryNamedUnderPath(self, "/Applications/NotThisApp.app/Contents/MacOS/NotThisApp", me.Name()) {
		t.Error("an executable path this process does not run under matched")
	}
	if AncestryNamedUnderPath(self, up.ExecPath, "not-"+me.Name()) {
		t.Error("a name this chain does not carry matched")
	}
	if launchd, ok := Describe(1); ok && AncestryNamedUnderPath(self, launchd.ExecPath, me.Name()) {
		t.Error("launchd's executable anchored a grant; a machine-wide name grant must be unreachable")
	}
	if AncestryNamedUnderPath(0, up.ExecPath, me.Name()) || AncestryNamedUnderPath(self, "", me.Name()) || AncestryNamedUnderPath(self, up.ExecPath, "") {
		t.Error("an empty pid, path or name matched")
	}
}
