// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSubscribeStreamsEventsAsRecorded(t *testing.T) {
	s, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()
	c := NewClient(socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan SessionEvent, 16)
	errc := make(chan error, 1)
	go func() { errc <- c.Subscribe(ctx, func(e SessionEvent) { events <- e }) }()
	waitFor(t, "subscription to register", func() bool { return s.subscriberCount() == 1 })

	// A fresh unlock and an explicit lock are the two events every session
	// has; they must arrive in that order, and match what history recorded.
	if _, err := c.WrapKey(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	var got []string
	for len(got) < 2 {
		select {
		case e := <-events:
			got = append(got, e.Kind)
		case <-time.After(5 * time.Second):
			t.Fatalf("got %v, want [unlock lock]", got)
		}
	}
	if got[0] != KindUnlock || got[1] != KindLock {
		t.Errorf("stream = %v, want [unlock lock]", got)
	}

	// Ending the context ends the call cleanly and unregisters the stream.
	cancel()
	if err := <-errc; err != context.Canceled {
		t.Errorf("Subscribe returned %v, want context.Canceled", err)
	}
	waitFor(t, "subscription to unregister", func() bool { return s.subscriberCount() == 0 })
}

func TestPublishMarksAFullSubscriberLagged(t *testing.T) {
	// The registry level is where lag is decided: publish runs under s.mu
	// and must never wait, so a subscriber whose channel is full is marked
	// and left behind. At the socket level the kernel's own buffer absorbs
	// a few events before the writer goroutine ever blocks, which is why
	// this is not tested by a peer that stops reading.
	s := NewServer(shortSocketPath(t), nil, time.Minute)
	s.subscribeBuffer = 1
	sub := s.subscribe()
	defer s.unsubscribe(sub)

	s.publish(SessionEvent{Kind: KindUnlock})
	select {
	case <-sub.lagged:
		t.Fatal("marked lagged with room in the buffer")
	default:
	}
	s.publish(SessionEvent{Kind: KindLock})
	select {
	case <-sub.lagged:
	default:
		t.Fatal("second event against a buffer of one did not mark the subscriber lagged")
	}
	// The event that fit is still there; the one that did not is gone, and
	// the subscriber re-syncs from history rather than receiving a gap.
	if got := <-sub.ch; got.Kind != KindUnlock {
		t.Errorf("buffered event = %q, want %q", got.Kind, KindUnlock)
	}
}

func TestSubscribeLaggedStreamIsHungUp(t *testing.T) {
	// A raw peer that subscribes and never reads. Its writer goroutine keeps
	// draining the channel into the kernel buffer until that fills and the
	// write itself blocks; the write deadline (readTimeout) then ends the
	// stream, and had the writer been free, the lagged mark would have. The
	// deadline is shortened so the test bounds the slow path too.
	s, socketPath, cleanup := startTestServerWith(t, time.Minute, nil, func(s *Server) {
		s.subscribeBuffer = 1
		s.readTimeout = 200 * time.Millisecond
	})
	defer cleanup()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(Request{Op: OpSubscribe}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	waitFor(t, "subscription to register", func() bool { return s.subscriberCount() == 1 })

	c := NewClient(socketPath)
	deadline := time.Now().Add(10 * time.Second)
	for s.subscriberCount() == 1 && time.Now().Before(deadline) {
		if _, err := c.WrapKey(bytes.Repeat([]byte{1}, 32)); err != nil {
			t.Fatalf("WrapKey: %v", err)
		}
		if err := c.Lock(); err != nil {
			t.Fatalf("Lock: %v", err)
		}
	}
	if s.subscriberCount() != 0 {
		t.Fatal("a peer that never reads was never dropped")
	}
}

func TestSubscribeEndsWithTheServer(t *testing.T) {
	s, socketPath, cleanup := startTestServer(t, time.Minute, nil)
	c := NewClient(socketPath)
	errc := make(chan error, 1)
	go func() { errc <- c.Subscribe(context.Background(), func(SessionEvent) {}) }()
	waitFor(t, "subscription to register", func() bool { return s.subscriberCount() == 1 })

	cleanup()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("Subscribe returned nil after the server closed; want a transport error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe did not return after the server closed")
	}
}
