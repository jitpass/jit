// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Spike S1: can the Secure Enclave hold jit's master key as a KEK, with the
// vault's 32-byte MEK sealed to it (ECIES) instead of stored in the clear?
// Runs ad-hoc signed, no profile: ephemeral SE keys only. See FINDINGS.md.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "sem.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
	"unsafe"
)

func cerr(e *C.char) error {
	if e == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(e))
	return fmt.Errorf("%s", C.GoString(e))
}

func seal(k unsafe.Pointer, pt []byte) ([]byte, error) {
	var n C.int
	var e *C.char
	out := C.sem_seal(k, (*C.uchar)(&pt[0]), C.int(len(pt)), &n, &e)
	if err := cerr(e); err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), n), nil
}

func open(k unsafe.Pointer, ct []byte, reason string) ([]byte, error) {
	var n C.int
	var e *C.char
	r := C.CString(reason)
	defer C.free(unsafe.Pointer(r))
	out := C.sem_open(k, (*C.uchar)(&ct[0]), C.int(len(ct)), r, &n, &e)
	if err := cerr(e); err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), n), nil
}

func pct(d []time.Duration, p float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*p)]
}

func main() {
	presence := flag.Bool("presence", false, "S2: userPresence key, prompts on open (needs a human)")
	n := flag.Int("n", 200, "iterations for timing")
	sealOnly := flag.Bool("seal-only", false, "stop after sealing: proves a presence key seals with no prompt")
	flag.Parse()

	var e *C.char
	p := 0
	if *presence {
		p = 1
	}
	t0 := time.Now()
	k := C.sem_new_key(C.int(p), &e)
	if err := cerr(e); err != nil {
		fmt.Println("FAIL new key:", err)
		os.Exit(1)
	}
	defer C.sem_free_key(k)
	fmt.Printf("keygen (SE, ephemeral, presence=%v): %v\n", *presence, time.Since(t0))

	mek := make([]byte, 32)
	_, _ = rand.Read(mek)

	// 1. Seal uses only the public half: must not prompt, even for presence.
	t0 = time.Now()
	blob, err := seal(k, mek)
	if err != nil {
		fmt.Println("FAIL seal:", err)
		os.Exit(1)
	}
	fmt.Printf("seal 32-byte MEK: %v, blob %d bytes (65 ephemeral pub + 32 ct + 16 tag)\n", time.Since(t0), len(blob))

	if *sealOnly {
		return
	}
	// 2. Open returns the exact MEK.
	got, err := open(k, blob, "unlock jit vault (spike)")
	if err != nil {
		fmt.Println("FAIL open:", err)
		os.Exit(1)
	}
	fmt.Println("round trip identical:", bytes.Equal(got, mek))

	// 3. Tamper: a flipped byte must fail, not return garbage.
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 1
	if _, err := open(k, bad, "spike"); err == nil {
		fmt.Println("FAIL tamper accepted")
		os.Exit(1)
	}
	fmt.Println("tampered blob refused: true")

	// 4. Another SE key cannot open it.
	k2 := C.sem_new_key(0, &e)
	if err := cerr(e); err != nil {
		fmt.Println("FAIL key2:", err)
		os.Exit(1)
	}
	_, err = open(k2, blob, "spike")
	C.sem_free_key(k2)
	fmt.Println("other SE key refused:", err != nil)

	if *presence {
		return
	}
	// 5. Latency: open (the per-unlock cost) and raw ECDH (a per-grant derive).
	var opens, ecdhs []time.Duration
	for i := 0; i < *n; i++ {
		t := time.Now()
		if _, err := open(k, blob, "spike"); err != nil {
			fmt.Println("FAIL open loop:", err)
			os.Exit(1)
		}
		opens = append(opens, time.Since(t))
		t = time.Now()
		if C.sem_ecdh(k, &e) != 32 {
			fmt.Println("FAIL ecdh:", cerr(e))
			os.Exit(1)
		}
		ecdhs = append(ecdhs, time.Since(t))
	}
	fmt.Printf("open  x%d: p50 %v  p99 %v\n", *n, pct(opens, .5), pct(opens, .99))
	fmt.Printf("ecdh  x%d: p50 %v  p99 %v (includes a software peer keygen)\n", *n, pct(ecdhs, .5), pct(ecdhs, .99))
}
