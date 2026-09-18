// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/json"
	"io"
	"net"
	"time"
)

// This file is OpSubscribe: the registry recordEvent fans into, and the
// goroutine that turns one subscriber's channel into JSON lines on its
// connection. It exists for renderers that show the session live (the menu
// bar app, `jit audit -f`) so they stop polling "history"; it adds no
// information that call does not already return.

// defaultSubscribeBuffer is how many events a subscriber may fall behind
// before it is disconnected. The ring itself holds MaxSessionEvents; a
// subscriber that has not drained sixty-four of them is not reading at all,
// and a reader that is not reading must not be able to pin memory in a
// process that lives for weeks. Disconnecting is the honest signal: the
// client re-syncs from "history", which loses nothing.
const defaultSubscribeBuffer = 64

// subscriber is one live stream. ch carries events; lagged is closed by the
// publisher the first time a send would block, and stays closed.
type subscriber struct {
	ch     chan SessionEvent
	lagged chan struct{}
	// broker marks a stream that answers consent requests (consentbroker.go);
	// it receives KindPending events on top of the recorded ones.
	broker bool
}

func (s *Server) subscribe(broker bool) *subscriber {
	sub := &subscriber{ch: make(chan SessionEvent, s.subscribeBuffer), lagged: make(chan struct{}), broker: broker}
	s.subMu.Lock()
	if s.subscribers == nil {
		s.subscribers = map[*subscriber]struct{}{}
	}
	s.subscribers[sub] = struct{}{}
	s.subMu.Unlock()
	return sub
}

func (s *Server) unsubscribe(sub *subscriber) {
	s.subMu.Lock()
	delete(s.subscribers, sub)
	s.subMu.Unlock()
	if sub.broker {
		s.brokerLeft()
	}
}

// subscriberCount is for tests, which need to know a stream is registered
// before they provoke the events it should carry.
func (s *Server) subscriberCount() int {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	return len(s.subscribers)
}

// publish hands e to every live subscriber without blocking. Called from
// recordEvent under s.mu, which is why it must never wait: a stalled peer
// would otherwise stall every unlock and lock in the agent. A full channel
// marks the subscriber lagged; its writer goroutine sees that and hangs up.
func (s *Server) publish(e SessionEvent) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for sub := range s.subscribers {
		select {
		case sub.ch <- e:
		default:
			select {
			case <-sub.lagged:
			default:
				close(sub.lagged)
			}
		}
	}
}

// PublishLive streams e to every subscriber without recording it: no ring,
// no durable trail, so "history" never returns it. For notices whose durable
// half is written later, collapsed (KindServeStart). Never blocks, like
// publish, so it is safe on a mount's serve path.
func (s *Server) PublishLive(e SessionEvent) {
	s.publish(e)
}

// serveSubscription owns conn for the life of the stream. The peer has
// already been verified same-user and its request decoded; nothing here
// needs the vault, so it never touches the session and never prompts.
func (s *Server) serveSubscription(conn net.Conn, broker bool) {
	sub := s.subscribe(broker)
	defer s.unsubscribe(sub)

	// One document acknowledges the subscription, in the same shape every
	// other op answers with, so a client can tell "subscribed" from "refused"
	// before it starts decoding events.
	_ = conn.SetWriteDeadline(time.Now().Add(s.readTimeout))
	if err := json.NewEncoder(conn).Encode(Response{OK: true, Protocol: Protocol}); err != nil {
		return
	}

	// A peer that hangs up sends nothing further; the only way to notice is
	// to read. This goroutine's Read returns on EOF (or on our own Close),
	// which ends the select below. Anything it does read is discarded: the
	// stream is one-way after the request.
	peerGone := make(chan struct{})
	go func() {
		defer close(peerGone)
		_, _ = io.Copy(io.Discard, conn)
	}()

	enc := json.NewEncoder(conn)
	for {
		select {
		case e := <-sub.ch:
			_ = conn.SetWriteDeadline(time.Now().Add(s.readTimeout))
			if err := enc.Encode(e); err != nil {
				return
			}
		case <-sub.lagged:
			return
		case <-peerGone:
			return
		case <-s.shutdown:
			return
		}
	}
}
