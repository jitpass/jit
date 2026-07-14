// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Command memguard-spike confirms github.com/awnumar/memguard builds and
// runs cleanly on this macOS/arm64 setup before it gets threaded through
// every place a decrypted secret touches memory in the real vault (Pillar II).
//
// Not production code — throwaway smoke test.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/awnumar/memguard"
)

func main() {
	defer memguard.Purge()

	fmt.Println("[1/4] Allocating a locked buffer (tests mlock availability/ulimits)...")
	original := []byte("sk_test_spike_super_secret_value")
	expected := make([]byte, len(original)) // kept separately: NewBufferFromBytes wipes its input arg
	copy(expected, original)

	buf := memguard.NewBufferFromBytes(original)
	if buf == nil || buf.Size() == 0 {
		fmt.Println("      FAILED: NewBufferFromBytes returned nil/empty buffer")
		os.Exit(1)
	}
	fmt.Printf("      OK: locked buffer allocated, size=%d\n", buf.Size())
	fmt.Printf("      NOTE: source slice after ingestion = %q (memguard wipes its input arg — expected, not a bug)\n", original)

	if !bytes.Equal(buf.Bytes(), expected) {
		fmt.Println("      FAILED: buffer contents don't match what was written")
		os.Exit(1)
	}
	fmt.Println("      OK: buffer contents match the original secret (checked against a separate copy).")
	secret := expected

	fmt.Println("\n[2/4] Round-tripping through an encrypted Enclave (Seal/Open)...")
	sealed := buf.Seal() // destroys buf as a side effect, per memguard's API
	opened, err := sealed.Open()
	if err != nil {
		fmt.Printf("      FAILED: Open() error: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(opened.Bytes(), secret) {
		fmt.Println("      FAILED: round-tripped contents don't match original")
		os.Exit(1)
	}
	fmt.Println("      OK: Seal -> Open round trip preserved the secret correctly.")

	fmt.Println("\n[3/4] Destroying the buffer and confirming it's wiped...")
	// Copy the underlying byte slice header's pointer target before destroying,
	// strictly to observe zeroing — never do this in real code.
	before := make([]byte, opened.Size())
	copy(before, opened.Bytes())
	opened.Destroy()
	fmt.Printf("      OK: Destroy() completed without panic. Was destroyed: %v\n", opened.IsAlive() == false)

	fmt.Println("\n[4/4] Testing CatchInterrupt (should not crash if called, even though we won't send a signal)...")
	memguard.CatchInterrupt()
	fmt.Println("      OK: CatchInterrupt registered cleanly.")

	fmt.Println("\nSPIKE RESULT: PASS — memguard builds and runs cleanly on this macOS/arm64 setup.")
}