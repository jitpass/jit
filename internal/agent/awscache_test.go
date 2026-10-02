// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var awsCreds = []byte(`{"Version":1,"AccessKeyId":"ASIACACHED","SecretAccessKey":"s","SessionToken":"t"}`)

// readAWS does what `jit aws-sso` does before it may fill the cache: a
// consented unwrap of an aws-class secret.
func readAWS(t *testing.T, c *Client) {
	t.Helper()
	wrapped, err := c.WrapKeyLabeled(bytes.Repeat([]byte{7}, 32), "aws-sso/cache", awsClass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UnwrapKeyLabeled(wrapped, "aws-sso/cache", awsClass); err != nil {
		t.Fatal(err)
	}
}

func TestAWSCacheServesWhatAProvenReaderPut(t *testing.T) {
	_, socket, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()
	c := NewClient(socket)
	readAWS(t, c)
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.AWSCacheGet("dev")
	if err != nil || !ok || !bytes.Equal(got, awsCreds) {
		t.Fatalf("get: %q, %v, %v", got, ok, err)
	}
	if _, ok, _ := c.AWSCacheGet("prod"); ok {
		t.Fatal("served another profile's credentials")
	}
}

// The attack the proof exists for: a socket client that read no AWS
// credential plants credentials for an account it controls.
func TestAWSCacheRefusesAPlantedFill(t *testing.T) {
	_, socket, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()
	c := NewClient(socket)
	if _, _, err := c.Unlock(); err != nil {
		t.Fatal(err)
	}
	err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "just read an AWS credential") {
		t.Fatalf("a fill with no prior aws read: %v", err)
	}
	// Reading some OTHER class of secret proves nothing about AWS.
	wrapped, _ := c.WrapKeyLabeled(bytes.Repeat([]byte{7}, 32), "myapp/API_KEY", "dotenv")
	if _, err := c.UnwrapKeyLabeled(wrapped, "myapp/API_KEY", "dotenv"); err != nil {
		t.Fatal(err)
	}
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a dotenv read let the caller fill the AWS cache")
	}
	if _, ok, _ := c.AWSCacheGet("dev"); ok {
		t.Fatal("a refused fill was served")
	}
}

// A proof goes stale: the fetch it vouches for is capped at two minutes.
func TestAWSCacheProofExpires(t *testing.T) {
	_, socket, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()
	c := NewClient(socket)
	readAWS(t, c)
	real := awsNow
	t.Cleanup(func() { awsNow = real })
	awsNow = func() time.Time { return real().Add(awsCacheProofTTL + time.Minute) }
	if err := c.AWSCachePut("dev", awsCreds, awsNow().Add(time.Hour)); err == nil {
		t.Fatal("a stale proof filled the cache")
	}
}

// Credentials close to expiry are never served (botocore would refresh at
// once), and a claimed expiry past any role session is capped.
func TestAWSCacheExpiry(t *testing.T) {
	s, socket, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()
	c := NewClient(socket)
	readAWS(t, c)
	if err := c.AWSCachePut("short", awsCreds, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := c.AWSCacheGet("short"); ok {
		t.Fatal("served credentials with 10 minutes left")
	}
	if err := c.AWSCachePut("long", awsCreds, time.Now().Add(1000*time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.awsCacheMu.Lock()
	e := s.awsCache["long"]
	s.awsCacheMu.Unlock()
	if e.expires.After(time.Now().Add(awsCacheMaxLife + time.Minute)) {
		t.Fatalf("expiry %v not capped", e.expires)
	}
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	real := awsNow
	t.Cleanup(func() { awsNow = real })
	awsNow = func() time.Time { return real().Add(50 * time.Minute) }
	if _, ok, _ := c.AWSCacheGet("dev"); ok {
		t.Fatal("served credentials that had aged into the refresh window")
	}
}

// The cache rides the session: a re-lock drops it, and a locked vault
// answers a miss without a challenge of its own.
func TestAWSCacheDiesWithTheSession(t *testing.T) {
	var calls int32
	_, socket, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()
	c := NewClient(socket)
	readAWS(t, c)
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := c.Lock(); err != nil {
		t.Fatal(err)
	}
	before := atomic.LoadInt32(&calls)
	if _, ok, err := c.AWSCacheGet("dev"); ok || err != nil {
		t.Fatalf("after lock: ok %v err %v", ok, err)
	}
	if atomic.LoadInt32(&calls) != before {
		t.Fatal("a cache read on a locked vault prompted")
	}
	// And the proof went with it: a fill now needs a fresh read.
	if _, _, err := c.Unlock(); err != nil {
		t.Fatal(err)
	}
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a proof survived the lock")
	}
}

func TestAWSCacheClear(t *testing.T) {
	_, socket, cleanup := startTestServer(t, time.Minute, nil)
	defer cleanup()
	c := NewClient(socket)
	readAWS(t, c)
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := c.AWSCacheClear(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := c.AWSCacheGet("dev"); ok {
		t.Fatal("served after clear")
	}
}

// A cache read is a credential read: it passes the consent gate, naming
// the caller, exactly as the unwrap it replaces would.
func TestAWSCacheReadIsConsented(t *testing.T) {
	var deny atomic.Bool
	_, socket, launcher := startConsentServer(t, &deny)
	c := NewClient(socket)
	readAWS(t, c) // as /usr/local/bin/aws, approved
	if err := c.AWSCachePut("dev", awsCreds, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.AWSCacheGet("dev"); err != nil || !ok {
		t.Fatalf("the approved launcher: %v, %v", ok, err)
	}
	// Another program asks; the human declines.
	other := "/tmp/evil"
	launcher.Store(&other)
	deny.Store(true)
	if _, ok, err := c.AWSCacheGet("dev"); err == nil || ok {
		t.Fatalf("a declined program got cached credentials: ok %v err %v", ok, err)
	}
}
