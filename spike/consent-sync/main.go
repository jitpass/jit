// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command consent-sync answers what the side-panel consent design needs
// before anything is built (design mockup: the Asking block in the menu
// bar panel, Touch ID at once, no Allow button):
//
//  1. Can the service cancel a Touch ID dialog that is already on screen,
//     on both of jit's paths (keychain evaluatePolicy, and a Secure Enclave
//     key with user presence), so the panel's Deny takes the dialog down?
//  2. With the service sending the request first, waiting at most -wait
//     for the panel's "shown", then raising the Touch ID, how far apart do
//     the panel and the dialog appear?
//  3. Does the panel, a non-activating floating NSPanel, take focus from
//     the dialog?
//
// This stands in for jit's service: it raises a REAL dialog, but it never
// opens the vault, never touches the keychain, never talks to the running
// service, and the enclave key is ephemeral (made for one prompt, never
// stored). The panel is panel/main.swift. run.sh drives the scenarios.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include <stdlib.h>
#include "prompt.h"
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"
)

type msg struct {
	T      string `json:"t"`
	ID     int    `json:"id,omitempty"`
	NS     int64  `json:"ns,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Stolen *bool  `json:"stolen,omitempty"`
	OK     *bool  `json:"ok,omitempty"`
	Code   int64  `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// timeline is every timestamp one trial produced, on one clock
// (CLOCK_REALTIME, same machine for both processes).
type timeline struct {
	mu          sync.Mutex
	Sent        int64  `json:"pending_sent_ns"`
	Shown       int64  `json:"panel_shown_ns,omitempty"`
	WaitedOut   bool   `json:"wait_expired"`
	EvalStart   int64  `json:"prompt_start_ns"`
	DialogSeen  int64  `json:"dialog_seen_ns,omitempty"`
	DialogOwner string `json:"dialog_owner,omitempty"`
	Deny        int64  `json:"deny_ns,omitempty"`
	DialogGone  int64  `json:"dialog_gone_ns,omitempty"`
	End         int64  `json:"prompt_end_ns"`
	FocusStolen *bool  `json:"focus_stolen,omitempty"`
	OK          bool   `json:"approved"`
	Code        int64  `json:"code"`
	Domain      string `json:"domain,omitempty"`
	Msg         string `json:"error,omitempty"`
}

func main() {
	mode := flag.String("mode", "enclave", "which prompt: enclave (a Secure Enclave key with user presence) or keychain (evaluatePolicy)")
	sock := flag.String("sock", "", "unix socket the panel connects to (required unless -no-panel)")
	noPanel := flag.Bool("no-panel", false, "run with no panel at all: the prompt must start at once")
	wait := flag.Duration("wait", 250*time.Millisecond, "longest wait for the panel's \"shown\" before raising the Touch ID")
	connectWait := flag.Duration("connect-wait", 10*time.Second, "how long to wait for the panel to connect")
	flag.Parse()

	reason := "unlock the vault for profile \"release-bot\", launched by claude (consent-sync spike)"
	tl := &timeline{}

	var conn net.Conn
	if !*noPanel {
		if *sock == "" {
			fmt.Fprintln(os.Stderr, "-sock is required unless -no-panel")
			os.Exit(2)
		}
		_ = os.Remove(*sock)
		ln, err := net.Listen("unix", *sock)
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
		defer ln.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				accepted <- c
			}
		}()
		select {
		case conn = <-accepted:
		case <-time.After(*connectWait):
			fmt.Fprintln(os.Stderr, "no panel connected; run with -no-panel to test that case")
			os.Exit(1)
		}
		defer conn.Close()
	}

	shown := make(chan struct{}, 1)
	var wmu sync.Mutex
	send := func(m msg) {
		if conn == nil {
			return
		}
		b, _ := json.Marshal(m)
		wmu.Lock()
		_, _ = conn.Write(append(b, '\n'))
		wmu.Unlock()
	}

	// Everything the panel reports, stamped into the timeline as it comes.
	// A deny cancels the prompt from this goroutine, while the prompt
	// itself blocks another: the real service's shape.
	readerDone := make(chan struct{})
	if conn != nil {
		go func() {
			defer close(readerDone)
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				var m msg
				if json.Unmarshal(sc.Bytes(), &m) != nil {
					continue
				}
				tl.mu.Lock()
				switch m.T {
				case "shown":
					tl.Shown = m.NS
					select {
					case shown <- struct{}{}:
					default:
					}
				case "dialog_seen":
					if tl.DialogSeen == 0 {
						tl.DialogSeen, tl.DialogOwner = m.NS, m.Owner
					}
				case "dialog_gone":
					tl.DialogGone = m.NS
				case "focus":
					tl.FocusStolen = m.Stolen
				case "deny":
					tl.Deny = m.NS
					tl.mu.Unlock()
					C.cancel_prompt()
					continue
				}
				tl.mu.Unlock()
			}
		}()
	} else {
		close(readerDone)
	}

	tl.Sent = int64(C.spike_now_ns())
	send(msg{T: "pending", ID: 1, NS: tl.Sent, Reason: reason})

	// The one change the design makes to the service: it no longer waits
	// for an Allow. It waits at most -wait for "the panel is on screen",
	// and never at all without a panel.
	if conn != nil {
		select {
		case <-shown:
		case <-time.After(*wait):
			tl.mu.Lock()
			tl.WaitedOut = true
			tl.mu.Unlock()
		}
	}

	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	var r C.PromptResult
	switch *mode {
	case "keychain":
		r = C.prompt_keychain(cr)
	case "enclave":
		r = C.prompt_enclave(cr)
	case "dry":
		// No dialog: checks the socket, the panel and the timeline end to
		// end. It "returns" after a second, or at once on a deny.
		r = C.PromptResult{start_ns: C.spike_now_ns()}
		for i := 0; i < 100; i++ {
			tl.mu.Lock()
			denied := tl.Deny != 0
			tl.mu.Unlock()
			if denied {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		r.end_ns = C.spike_now_ns()
		r.ok = 1
	default:
		fmt.Fprintln(os.Stderr, "unknown -mode", *mode)
		os.Exit(2)
	}

	tl.mu.Lock()
	tl.EvalStart, tl.End = int64(r.start_ns), int64(r.end_ns)
	tl.OK, tl.Code = r.ok == 1, int64(r.code)
	if r.domain != nil {
		tl.Domain = C.GoString(r.domain)
		C.free(unsafe.Pointer(r.domain))
	}
	if r.msg != nil {
		tl.Msg = C.GoString(r.msg)
		C.free(unsafe.Pointer(r.msg))
	}
	ok := tl.OK
	tl.mu.Unlock()

	send(msg{T: "outcome", ID: 1, OK: &ok, Code: int64(r.code)})
	// Give the panel time to report the dialog going away and the focus
	// check (it runs 300 ms after the panel shows).
	if conn != nil {
		select {
		case <-readerDone:
		case <-time.After(1500 * time.Millisecond):
		}
	}
	report(*mode, tl)
}

func ms(from, to int64) string {
	if from == 0 || to == 0 {
		return "—"
	}
	return fmt.Sprintf("%+.0f ms", float64(to-from)/1e6)
}

func report(mode string, tl *timeline) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	fmt.Printf("mode=%s\n", mode)
	fmt.Printf("  request sent        0 ms\n")
	fmt.Printf("  panel shown         %s\n", ms(tl.Sent, tl.Shown))
	fmt.Printf("  prompt started      %s%s\n", ms(tl.Sent, tl.EvalStart), map[bool]string{true: "  (the wait for \"shown\" ran out)", false: ""}[tl.WaitedOut])
	fmt.Printf("  dialog on screen    %s  %s\n", ms(tl.Sent, tl.DialogSeen), tl.DialogOwner)
	fmt.Printf("  panel vs dialog     %s  (dialog minus panel; the goal is within 150 ms)\n", ms(tl.Shown, tl.DialogSeen))
	if tl.Deny != 0 {
		fmt.Printf("  deny sent           %s\n", ms(tl.Sent, tl.Deny))
		fmt.Printf("  dialog gone         %s  (after the deny: %s)\n", ms(tl.Sent, tl.DialogGone), ms(tl.Deny, tl.DialogGone))
	} else if tl.DialogGone != 0 {
		fmt.Printf("  dialog gone         %s\n", ms(tl.Sent, tl.DialogGone))
	}
	fmt.Printf("  prompt returned     %s\n", ms(tl.Sent, tl.End))
	if tl.FocusStolen != nil {
		fmt.Printf("  panel took focus    %v\n", *tl.FocusStolen)
	}
	if tl.OK {
		fmt.Printf("  result              approved\n")
	} else {
		fmt.Printf("  result              refused: code %d (%s) %s\n", tl.Code, tl.Domain, tl.Msg)
	}
	b, _ := json.Marshal(tl)
	fmt.Printf("  json %s\n", b)
}
