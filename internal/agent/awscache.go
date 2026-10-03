// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"time"

	"github.com/jitpass/jit/internal/lineage"
)

// The AWS SSO role-credential cache (design/aws-sso-sealed.md D7).
//
// `jit aws-sso` runs AWS's own CLI once per credential fetch, about 260 ms
// of Python, and the role credentials it gets live an hour. This keeps them
// here, in the service's memory, so the next fetch for the same profile is
// a socket round trip. Never on disk (that is what ~/.aws/cli/cache was),
// dropped on every re-lock, and served only while they have more than
// awsCacheMargin left, so an SDK never receives credentials it would
// refresh at once.
//
// The danger in a cache is a filler that lies: a socket client planting
// credentials for an account it controls, so the user's next `aws s3 cp`
// uploads there. So:
//
//   - a read (aws_cache_get) passes the same consent gate an aws unwrap
//     does, naming the caller, and needs a live session; a miss prompts
//     nothing, so the caller's fallback (a real unwrap) asks once;
//   - a write (aws_cache_put) is taken only from a process that completed
//     a consented unwrap of an aws-class secret in this session, within
//     awsCacheProofTTL, anchored to its fork time. Such a process already
//     held a credential worth more than a cache entry; a bare socket client
//     holds nothing and is refused.
//
// Caller identity is the anchor of the proof, not a decision about who is
// trusted: the decision was the consent the unwrap passed.

// awsClass is the vault class AWS secrets carry (vault.ClassAWS; this
// package never imports the vault).
const awsClass = "aws"

const (
	// awsCacheMargin: serve only credentials with at least this long left.
	// botocore refreshes inside 15 minutes of expiry; anything shorter would
	// come straight back.
	awsCacheMargin = 15 * time.Minute
	// awsCacheProofTTL bounds how long after its unwrap a process may fill
	// the cache: the fetch it does in between is capped at 2 minutes.
	awsCacheProofTTL = 5 * time.Minute
	// awsCacheMaxLife caps a claimed expiry (role sessions are at most 12h).
	awsCacheMaxLife = 12 * time.Hour
	// awsCacheMaxEntry bounds one entry: credential_process JSON is ~1 KB.
	awsCacheMaxEntry = 64 << 10
)

type awsCacheEntry struct {
	data    []byte
	expires time.Time
}

type awsCacheProof struct {
	start int64 // the process's fork time, so a recycled pid proves nothing
	at    time.Time
}

// awsNow is the cache's clock, a var so a test can move it.
var awsNow = time.Now

// noteAWSUnwrap records that c completed a consented aws unwrap.
func (s *Server) noteAWSUnwrap(c *caller) {
	if c == nil || c.pid <= 0 {
		return
	}
	start, ok := lineage.ProcessStartTime(c.pid)
	if !ok {
		return
	}
	s.awsCacheMu.Lock()
	defer s.awsCacheMu.Unlock()
	if s.awsProofs == nil {
		s.awsProofs = map[int32]awsCacheProof{}
	}
	s.awsProofs[c.pid] = awsCacheProof{start: start, at: awsNow()}
}

func (s *Server) sessionLive() bool {
	mek := s.peekSession()
	if mek == nil {
		return false
	}
	wipe(mek)
	return true
}

func (s *Server) awsCacheGet(req Request, c *caller) Response {
	if req.CacheKey == "" {
		return Response{OK: false, Error: "aws_cache_get: missing cache_key"}
	}
	// A locked vault has no cache (clearAWSCache ran at the lock); asking
	// would only add a prompt in front of the real unwrap's.
	if !s.sessionLive() {
		return Response{OK: true}
	}
	s.awsCacheMu.Lock()
	e, ok := s.awsCache[req.CacheKey]
	s.awsCacheMu.Unlock()
	if !ok || e.expires.Sub(awsNow()) < awsCacheMargin {
		return Response{OK: true}
	}
	if err := s.gateConsent(awsClass, c, req.Op); err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	s.recordUse(OpAWSCacheGet, c, "aws-sso:"+req.CacheKey)
	return Response{OK: true, Data: append([]byte(nil), e.data...)}
}

func (s *Server) awsCachePut(req Request, c *caller) Response {
	if req.CacheKey == "" || len(req.Data) == 0 || len(req.Data) > awsCacheMaxEntry {
		return Response{OK: false, Error: "aws_cache_put: a cache_key and up to 64 KB of data are required"}
	}
	if !s.sessionLive() {
		return Response{OK: false, Error: "aws_cache_put: the vault is locked"}
	}
	now := awsNow()
	start, startOK := int64(0), false
	if c != nil {
		start, startOK = lineage.ProcessStartTime(c.pid)
	}
	s.awsCacheMu.Lock()
	defer s.awsCacheMu.Unlock()
	p, ok := s.awsProofs[callerPID(c)]
	if !ok || !startOK || p.start != start || now.Sub(p.at) > awsCacheProofTTL {
		return Response{OK: false, Error: "aws_cache_put: only a process that has just read an AWS credential may fill the cache"}
	}
	expires := time.Unix(req.ExpiresUnix, 0)
	if expires.Sub(now) < awsCacheMargin {
		return Response{OK: true} // too close to expiry to be worth serving
	}
	if expires.Sub(now) > awsCacheMaxLife {
		expires = now.Add(awsCacheMaxLife)
	}
	if s.awsCache == nil {
		s.awsCache = map[string]awsCacheEntry{}
	}
	s.awsCache[req.CacheKey] = awsCacheEntry{data: append([]byte(nil), req.Data...), expires: expires}
	return Response{OK: true}
}

func callerPID(c *caller) int32 {
	if c == nil {
		return 0
	}
	return c.pid
}

// clearAWSCache drops every cached credential and every fill proof: at a
// re-lock, a sign-out, a new login.
func (s *Server) clearAWSCache() {
	s.awsCacheMu.Lock()
	defer s.awsCacheMu.Unlock()
	for k, e := range s.awsCache {
		for i := range e.data {
			e.data[i] = 0
		}
		delete(s.awsCache, k)
	}
	s.awsProofs = nil
}

// AWSCacheGet asks for a profile's cached credentials: ok is false on a
// miss (or a service too old to know the op), and the caller then fetches.
func (c *Client) AWSCacheGet(profile string) (data []byte, ok bool, err error) {
	resp, err := c.call(Request{Op: OpAWSCacheGet, CacheKey: profile})
	if err != nil {
		return nil, false, err
	}
	return resp.Data, len(resp.Data) > 0, nil
}

// AWSCachePut offers credentials just fetched for profile, expiring at
// expires. Refused unless this process just read an AWS credential.
func (c *Client) AWSCachePut(profile string, data []byte, expires time.Time) error {
	_, err := c.call(Request{Op: OpAWSCachePut, CacheKey: profile, Data: data, ExpiresUnix: expires.Unix()})
	return err
}

// AWSCacheClear empties the cache.
func (c *Client) AWSCacheClear() error {
	_, err := c.call(Request{Op: OpAWSCacheClear})
	return err
}
