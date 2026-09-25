// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// S3c/S3b: the jit shape. A Go binary named jit, the helper bundle's main
// executable, reached through a symlink (S3c) and started by launchd (S3b).
// Same test tag and access group as S3a.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security
#include "sek.h"
*/
import "C"

import (
	"fmt"
	"os"
)

func main() {
	exe, _ := os.Executable()
	fmt.Printf("argv0=%s executable=%s ppid=%d\n", os.Args[0], exe, os.Getppid())
	op := ""
	if len(os.Args) > 1 {
		op = os.Args[1]
	}
	rc := 2
	switch op {
	case "create":
		rc = int(C.sek_create())
	case "find":
		rc = int(C.sek_find())
	case "delete":
		rc = int(C.sek_delete())
	case "all": // S3b: one launchd run does the whole cycle
		rc = int(C.sek_delete()) | int(C.sek_create()) | int(C.sek_find()) | int(C.sek_delete())
	default:
		fmt.Println("usage: jit create|find|delete|all")
	}
	os.Stdout.Sync()
	os.Exit(rc)
}
