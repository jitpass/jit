// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"crypto/rand"
	"errors"
	"testing"
)

// fakeEnclave keeps the enclave contract in memory: a key that exists or not,
// sealing that never "prompts" and opening that records each reason, so the
// Wrapper's logic is testable without a signed, provisioned binary.
type fakeEnclave struct {
	exists  bool
	key     []byte // stands in for the private key
	opens   []string
	openErr error // returned by open instead of opening
	presErr error // returned by present
}

func newFake(t *testing.T) *fakeEnclave {
	t.Helper()
	return &fakeEnclave{}
}

func (f *fakeEnclave) present() (bool, error) {
	if f.presErr != nil {
		return false, f.presErr
	}
	return f.exists, nil
}

func (f *fakeEnclave) create() error {
	if f.presErr != nil {
		return f.presErr
	}
	f.key = make([]byte, 32)
	if _, err := rand.Read(f.key); err != nil {
		return err
	}
	f.exists = true
	return nil
}

func (f *fakeEnclave) remove() error {
	f.exists, f.key = false, nil
	return nil
}

func (f *fakeEnclave) seal(pt []byte) ([]byte, error) {
	if !f.exists {
		return nil, ErrNoKey
	}
	return seal(f.key, pt, []byte("fake-enclave"))
}

func (f *fakeEnclave) open(ct []byte, reason string) ([]byte, error) {
	f.opens = append(f.opens, reason)
	if f.openErr != nil {
		return nil, f.openErr
	}
	if !f.exists {
		return nil, ErrNoKey
	}
	return open(f.key, ct, []byte("fake-enclave"))
}

func TestFakeHonoursTheContract(t *testing.T) {
	f := newFake(t)
	if _, err := f.seal([]byte("x")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("seal before create: %v, want ErrNoKey", err)
	}
	if err := f.create(); err != nil {
		t.Fatal(err)
	}
	ct, err := f.seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := f.open(ct, "r")
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open = %q, %v", pt, err)
	}
}
