// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import "testing"

func TestIsProductionIndicator(t *testing.T) {
	// These four cases are RFC.md §4's own explicit examples — the whole
	// point of the custom-boundary regex is to satisfy exactly these.
	cases := []struct {
		input string
		want  bool
	}{
		{"PROD_DB_URL", true},
		{"evm-prod-ro-endpoint", true},
		{"nonprod", false},
		{"product", false},
		// Additional boundary coverage beyond RFC's own examples.
		{"prod", true},
		{"PRODUCTION_API_KEY", true},
		{"production", true},
		{"productive", false},
		{"myproduct", false},
		{"db.prod.internal", true},
		{"unproductive", false},
		{"", false},
	}
	for _, c := range cases {
		got := IsProductionIndicator(c.input)
		if got != c.want {
			t.Errorf("IsProductionIndicator(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestMatchPublicIP(t *testing.T) {
	cases := []struct {
		input   string
		wantIP  string
		wantOK  bool
		comment string
	}{
		{"postgres://10.0.0.5:5432/db", "", false, "RFC1918 private (10.0.0.0/8)"},
		{"host=172.16.4.1", "", false, "RFC1918 private (172.16.0.0/12)"},
		{"192.168.1.1", "", false, "RFC1918 private (192.168.0.0/16)"},
		{"http://127.0.0.1:8080", "", false, "loopback — excluded despite being outside RFC1918"},
		{"169.254.1.1", "", false, "link-local — excluded despite being outside RFC1918"},
		{"0.0.0.0", "", false, "unspecified — excluded despite being outside RFC1918"},
		{"evm-prod-ro-endpoint=8.8.8.8", "8.8.8.8", true, "genuine public IP"},
		{"no ip here", "", false, "no match"},
	}
	for _, c := range cases {
		gotIP, gotOK := MatchPublicIP(c.input)
		if gotOK != c.wantOK || (gotOK && gotIP != c.wantIP) {
			t.Errorf("MatchPublicIP(%q) = (%q, %v), want (%q, %v) [%s]", c.input, gotIP, gotOK, c.wantIP, c.wantOK, c.comment)
		}
	}
}

func TestLooksLikeBareURL(t *testing.T) {
	cases := []struct {
		input   string
		want    bool
		comment string
	}{
		{"http://localhost:8080", true, "plain local tool endpoint (the real CAIDO_URL case)"},
		{"https://caido.example.com/api", true, "plain remote endpoint, short path"},
		{"not a url at all", false, "no http(s) prefix"},
		{"https://user:hunter2@db.internal/path", false, "userinfo present — treat as potentially credential-bearing"},
		// Literal split so GitHub push protection doesn't flag this fake
		// fixture as a real webhook; the compiled string is unchanged.
		{"https://hooks.slack.com" + "/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", false, "long opaque token segment — Slack webhook URLs ARE secrets"},
		{"", false, "empty string"},
	}
	for _, c := range cases {
		got := LooksLikeBareURL(c.input)
		if got != c.want {
			t.Errorf("LooksLikeBareURL(%q) = %v, want %v [%s]", c.input, got, c.want, c.comment)
		}
	}
}
