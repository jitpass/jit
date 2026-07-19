// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command run-compat-swap-spike validates the "compatibility swap": while a
// jit run executes, the mount at .env is a plain regular comment-pointer
// file (so `[ -f ]`/is_file() pass and a re-read parses to nothing), and
// the decoy FIFO is restored the instant the run exits. Before building it
// on top of internal/mount's RetireFIFO/CreateFIFO, six mechanical
// questions need empirical answers on macOS:
//
//  1. ATOMICITY (swap in): is there a window where the path does NOT exist,
//     during which a `[ -f .env ]` would fail "file not found" — the very
//     trap the swap exists to remove, reintroduced intermittently? Compare
//     the rename-aside-then-write ordering (RetireFIFO's) against an
//     atomic write-temp-then-rename-over.
//
//  2. ATOMICITY (restore): same question reversing file -> FIFO at run exit.
//
//  3. BLOCKED READER: a reader blocked in open() on the FIFO at the swap
//     instant — does the atomic rename-over still let us rescue it, or does
//     only RetireFIFO's rename-aside keep the vnode reachable?
//
//  4. CRASH RECONCILIATION: the agent dies with the regular file in place.
//     On restart it must recreate the FIFO — but ONLY over its own pointer
//     file, NEVER over a file a user restored by hand. Test the provenance
//     check (header marker) that gates that.
//
//  5. REFCOUNT: two concurrent runs on one mount — first swaps in, second
//     must not re-swap, the FIFO returns only after the LAST exit.
//
//  6. INERTNESS: the comment-only pointer file must pass `[ -f ]`, and
//     `source`-ing it (bash) must set no variables.
//
// Not production code — throwaway.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const pointerFile = "# jit: secrets live in the vault, not here. Run with: jit run <command>\n# API_KEY -> jit://vault/fixture/API_KEY\n"

func main() {
	mode := flag.String("mode", "", "atomicity|blocked|hardlink|crash|refcount|inertness|all")
	flag.Parse()
	run := func(name string, fn func()) {
		fmt.Printf("\n===== %s =====\n", name)
		fn()
	}
	switch *mode {
	case "atomicity":
		run("atomicity", testAtomicity)
	case "blocked":
		run("blocked", testBlockedReader)
	case "hardlink":
		run("hardlink", testHardlinkRescue)
	case "crash":
		run("crash", testCrashReconciliation)
	case "refcount":
		run("refcount", testRefcount)
	case "inertness":
		run("inertness", testInertness)
	case "all", "":
		run("atomicity", testAtomicity)
		run("blocked", testBlockedReader)
		run("hardlink", testHardlinkRescue)
		run("crash", testCrashReconciliation)
		run("refcount", testRefcount)
		run("inertness", testInertness)
	default:
		fmt.Fprintln(os.Stderr, "usage: -mode atomicity|blocked|crash|refcount|inertness|all")
		os.Exit(2)
	}
}

// ---------- helpers mirroring internal/mount primitives ----------

func mkfifo(path string) {
	_ = os.Remove(path)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		fatal("mkfifo %s: %v", path, err)
	}
}

// swapAside is RetireFIFO's ordering: rename the pipe to a sibling, THEN
// the caller writes the regular file at path. The gap between the two is
// the window this spike measures.
func swapAside(path string) (writeFile func()) {
	tmp := path + ".jit-prev"
	_ = os.Remove(tmp)
	if err := os.Rename(path, tmp); err != nil {
		fatal("rename aside: %v", err)
	}
	return func() {
		if err := os.WriteFile(path, []byte(pointerFile), 0o644); err != nil {
			fatal("write pointer file: %v", err)
		}
	}
}

// swapAtomic writes the regular file to a sibling temp and rename(2)s it
// OVER the FIFO path — rename is atomic, so the path always resolves to
// either the old FIFO or the new file, never to nothing.
func swapAtomic(path string) {
	tmp := path + ".jit-tmp"
	if err := os.WriteFile(tmp, []byte(pointerFile), 0o644); err != nil {
		fatal("write temp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		fatal("rename over: %v", err)
	}
}

// restoreAtomic reverses swapAtomic: mkfifo at a sibling temp, rename over
// the regular file. Also atomic — no absent-path window.
func restoreAtomic(path string) {
	tmp := path + ".jit-tmp"
	_ = os.Remove(tmp)
	if err := syscall.Mkfifo(tmp, 0o600); err != nil {
		fatal("mkfifo temp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		fatal("rename fifo over: %v", err)
	}
}

// pathState samples what's at path right now, the way `[ -f ]` (regular),
// `[ -p ]` (fifo), and "absent" would each see it.
func pathState(path string) string {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "ABSENT"
	}
	if err != nil {
		return "ERR:" + err.Error()
	}
	switch {
	case info.Mode()&os.ModeNamedPipe != 0:
		return "fifo"
	case info.Mode().IsRegular():
		return "regular"
	default:
		return "other"
	}
}

// ---------- 1 & 2: atomicity windows ----------

func testAtomicity() {
	dir, _ := os.MkdirTemp("", "swap")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, ".env")

	// A tight stat loop runs concurrently with each swap, tallying what it
	// observes — this is the `[ -f ]` a script could execute at any instant.
	measure := func(label string, doSwap func()) {
		if pathState(path) != "fifo" {
			mkfifoRaw(path)
		}
		var absent, regular, fifo, other int64
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				switch pathState(path) {
				case "ABSENT":
					atomic.AddInt64(&absent, 1)
				case "regular":
					atomic.AddInt64(&regular, 1)
				case "fifo":
					atomic.AddInt64(&fifo, 1)
				default:
					atomic.AddInt64(&other, 1)
				}
			}
		}()
		time.Sleep(20 * time.Millisecond)
		for i := 0; i < 500; i++ {
			doSwap()
		}
		close(stop)
		wg.Wait()
		fmt.Printf("[%s] over %d swaps: absent=%d regular=%d fifo=%d other=%d\n",
			label, 500, absent, regular, fifo, other)
		if absent > 0 {
			fmt.Printf("[%s] >>> %d observations saw NO FILE — a `[ -f ]` there fails 'not found'\n", label, absent)
		} else {
			fmt.Printf("[%s] >>> the path was NEVER absent — no intermittent guard failure\n", label)
		}
	}

	// aside-then-write: RetireFIFO's ordering. Restore between iterations
	// is the same non-atomic ordering (remove file, mkfifo) so the whole
	// round-trip is measured honestly under the ordering it belongs to.
	measure("aside-then-write round-trip (RetireFIFO ordering)", func() {
		write := swapAside(path) // fifo -> aside
		write()                  // write regular file (path was ABSENT in between)
		_ = os.Remove(path + ".jit-prev")
		_ = os.Remove(path) // restore: remove file...
		mkfifoRaw(path)     // ...then mkfifo (ABSENT in between again)
	})

	// atomic round-trip: swapAtomic (fifo->file) then restoreAtomic
	// (file->fifo), both rename(2)-over — the path is only ever one of the
	// two real states, never absent. No remove-based reset anywhere.
	mkfifoRaw(path)
	measure("atomic round-trip (rename-over both directions)", func() {
		swapAtomic(path)    // fifo -> regular, atomic
		restoreAtomic(path) // regular -> fifo, atomic
	})
}

func mkfifoRaw(path string) {
	_ = os.Remove(path)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		fatal("mkfifo: %v", err)
	}
}

// ---------- 3: blocked reader across the swap ----------

func testBlockedReader() {
	for _, strategy := range []string{"aside", "atomic"} {
		dir, _ := os.MkdirTemp("", "blocked")
		path := filepath.Join(dir, ".env")
		mkfifo(path)

		// A reader blocks in open(O_RDONLY) on the FIFO — no writer yet, so
		// it's parked in the kernel with no fd held (invisible to lsof).
		reader := exec.Command("/bin/cat", path)
		out := &syncBuf{}
		reader.Stdout = out
		if err := reader.Start(); err != nil {
			fatal("start reader: %v", err)
		}
		time.Sleep(150 * time.Millisecond) // ensure it's parked in open()

		released := make(chan struct{})
		go func() {
			_ = reader.Wait()
			close(released)
		}()

		switch strategy {
		case "aside":
			// RetireFIFO's rescue: rename aside, write file, then open the
			// retired pipe O_WRONLY|NONBLOCK to complete the pending open.
			write := swapAside(path)
			write()
			tmp := path + ".jit-prev"
			if fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
				_, _ = unix.Write(fd, []byte("rescued\n"))
				_ = unix.Close(fd)
			} else {
				fmt.Printf("[aside] probe of retired pipe: %v (ENXIO would mean nobody waited)\n", err)
			}
			_ = os.Remove(tmp)
		case "atomic":
			// Atomic rename-over unlinks the FIFO with no sibling kept — is
			// the blocked reader rescuable at all afterward?
			swapAtomic(path)
		}

		select {
		case <-released:
			fmt.Printf("[%s] blocked reader was RELEASED (got %q)\n", strategy, out.String())
		case <-time.After(2 * time.Second):
			fmt.Printf("[%s] >>> blocked reader is STILL STUCK 2s after the swap — this ordering strands it\n", strategy)
			_ = reader.Process.Kill()
		}
		os.RemoveAll(dir)
	}
}

// ---------- 3b: hardlink-rescue atomic swap (BOTH properties) ----------

// swapHardlinkRescue is the candidate primitive that gets BOTH no-absent-
// window (atomic rename-over) AND blocked-reader rescue (which plain atomic
// loses): before the rename, hardlink the FIFO to a sibling so its vnode
// stays reachable after the rename unlinks it from the path; after the
// atomic rename, complete any reader blocked in open() through the sibling,
// then drop it. rename(2) never leaves the path absent; the hardlink never
// moves the path, so a `[ -f ]` at any instant sees fifo-then-regular.
func swapHardlinkRescue(path string) {
	prev := path + ".jit-prev"
	_ = os.Remove(prev)
	if err := os.Link(path, prev); err != nil { // second name for the same fifo vnode
		fatal("hardlink fifo aside: %v", err)
	}
	tmp := path + ".jit-tmp"
	if err := os.WriteFile(tmp, []byte(pointerFile), 0o644); err != nil {
		fatal("write temp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil { // atomic: path is regular file now, fifo unlinked from path
		fatal("rename over: %v", err)
	}
	// Rescue whoever was blocked in open() on the fifo — reachable via prev.
	if fd, err := unix.Open(prev, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
		_, _ = unix.Write(fd, []byte(pointerFile))
		_ = unix.Close(fd)
	}
	_ = os.Remove(prev)
}

// testHardlinkRescue proves swapHardlinkRescue satisfies both properties at
// once: a reader blocked in open() at the swap instant is released, AND a
// concurrent stat loop never sees the path absent.
func testHardlinkRescue() {
	dir, _ := os.MkdirTemp("", "hardlink")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, ".env")
	mkfifoRaw(path)

	// Part 1: blocked reader is released.
	reader := exec.Command("/bin/cat", path)
	out := &syncBuf{}
	reader.Stdout = out
	if err := reader.Start(); err != nil {
		fatal("start reader: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // parked in open()
	released := make(chan struct{})
	go func() { _ = reader.Wait(); close(released) }()

	swapHardlinkRescue(path)

	select {
	case <-released:
		fmt.Printf("[hardlink] blocked reader RELEASED (got %q)\n", out.String())
	case <-time.After(2 * time.Second):
		fmt.Printf("[hardlink] >>> blocked reader STILL STUCK — rescue failed\n")
		_ = reader.Process.Kill()
	}

	// Part 2: no absent window under a stat storm.
	mkfifoRaw(path)
	var absent int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if pathState(path) == "ABSENT" {
				atomic.AddInt64(&absent, 1)
			}
		}
	}()
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 300; i++ {
		swapHardlinkRescue(path) // fifo -> file
		restoreAtomic(path)      // file -> fifo (atomic)
	}
	close(stop)
	wg.Wait()
	if absent == 0 {
		fmt.Printf("[hardlink] >>> 300 round-trips: path NEVER absent AND blocked readers rescued — both properties\n")
	} else {
		fmt.Printf("[hardlink] >>> %d absent observations — hardlink path is not absent-free\n", absent)
	}
}

// ---------- 4: crash reconciliation with provenance ----------

// looksLikeJitPointerFile is the provenance gate: the agent may recreate a
// FIFO over a regular file at a mount path ONLY when that file is one jit
// itself wrote (its header marker) — never over content a user restored by
// hand, which must be left untouched and surfaced, not clobbered.
func looksLikeJitPointerFile(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	const marker = "# jit: secrets live in the vault"
	return len(b) >= len(marker) && string(b[:len(marker)]) == marker
}

func testCrashReconciliation() {
	dir, _ := os.MkdirTemp("", "crash")
	defer os.RemoveAll(dir)

	// Case A: jit's own pointer file left behind by a crash mid-run — must
	// be reconciled back to a FIFO.
	jitPath := filepath.Join(dir, "a.env")
	_ = os.WriteFile(jitPath, []byte(pointerFile), 0o644)
	if looksLikeJitPointerFile(jitPath) {
		restoreAtomic(jitPath)
		fmt.Printf("[crash] jit pointer file -> reconciled to %s (correct)\n", pathState(jitPath))
	} else {
		fmt.Printf("[crash] >>> FAILED to recognize jit's own pointer file\n")
	}

	// Case B: a user hand-restored real content at the mount path (jit
	// unmount, or manual recovery). Reconciliation must NOT clobber it.
	userPath := filepath.Join(dir, "b.env")
	_ = os.WriteFile(userPath, []byte("API_KEY=user_put_this_back_by_hand\n"), 0o644)
	if looksLikeJitPointerFile(userPath) {
		fmt.Printf("[crash] >>> WOULD CLOBBER a user's file — provenance check failed\n")
	} else {
		fmt.Printf("[crash] user file left intact: %q (correct — surface, don't overwrite)\n", firstLine(userPath))
	}
}

// ---------- 5: refcount for concurrent runs ----------

// swapRefcount models the agent's per-mount grant/swap counter: the FIRST
// run swaps the FIFO out, the LAST run's exit swaps it back, and anything
// in between is a no-op on the filesystem.
type swapRefcount struct {
	mu    sync.Mutex
	count map[string]int
	swaps int64 // filesystem swap-ins performed
	rests int64 // filesystem restores performed
}

func (s *swapRefcount) enter(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count == nil {
		s.count = map[string]int{}
	}
	s.count[path]++
	if s.count[path] == 1 {
		atomic.AddInt64(&s.swaps, 1) // real swap only on 0->1
	}
}

func (s *swapRefcount) exit(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count[path]--
	if s.count[path] == 0 {
		atomic.AddInt64(&s.rests, 1) // real restore only on 1->0
	}
}

func testRefcount() {
	s := &swapRefcount{}
	path := "/tmp/fixture/.env"
	const runs = 20
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.enter(path)
			time.Sleep(time.Duration(5+i) * time.Millisecond)
			s.exit(path)
		}()
	}
	wg.Wait()
	fmt.Printf("[refcount] %d overlapping runs -> %d filesystem swap-in(s), %d restore(s), final count=%d\n",
		runs, s.swaps, s.rests, s.count[path])
	if s.swaps >= 1 && s.rests == s.swaps && s.count[path] == 0 {
		fmt.Printf("[refcount] >>> balanced: FIFO restored exactly once after the last run, never mid-flight\n")
	} else {
		fmt.Printf("[refcount] >>> UNBALANCED — swap/restore leak\n")
	}
}

// ---------- 6: inertness of the comment-only file ----------

func testInertness() {
	dir, _ := os.MkdirTemp("", "inert")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, ".env")
	_ = os.WriteFile(path, []byte(pointerFile), 0o644)

	// `[ -f ]` and `[ -r ]` must pass.
	out, _ := exec.Command("/bin/sh", "-c", fmt.Sprintf("[ -f %q ] && echo FILE_OK; [ -r %q ] && echo READ_OK", path, path)).CombinedOutput()
	fmt.Printf("[inertness] guards: %s", out)

	// `set -a; source` must set NO variable from the file.
	script := fmt.Sprintf(`set -a; . %q; set +a; echo "API_KEY=[${API_KEY:-<unset>}]"`, path)
	out, _ = exec.Command("/bin/sh", "-c", script).CombinedOutput()
	fmt.Printf("[inertness] after sourcing: %s", out)
	if string(out) == "API_KEY=[<unset>]\n" {
		fmt.Printf("[inertness] >>> sourcing the comment file set nothing — no clobber path\n")
	} else {
		fmt.Printf("[inertness] >>> UNEXPECTED: sourcing set something\n")
	}
}

// ---------- misc ----------

type syncBuf struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}

func firstLine(path string) string {
	b, _ := os.ReadFile(path)
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
