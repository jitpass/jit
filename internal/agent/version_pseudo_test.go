package agent

import "testing"

func TestIsPseudoVersion(t *testing.T) {
	pseudo := []string{
		"v1.9.1-0.20260919183123-44cfb0d9bfab+dirty",
		"v1.9.1-0.20260919183123-44cfb0d9bfab",
		"v0.0.0-20260919183123-44cfb0d9bfab",
		"v2.1.1-0.20260919183123-44cfb0d9bfab",
	}
	for _, v := range pseudo {
		if !isPseudoVersion(v) {
			t.Errorf("%q must be recognised as synthesized, not reported as a release", v)
		}
	}
	// Real tags, including the v2 ones this module's path keeps Go from
	// reaching, must still be reported when something stamps them.
	for _, v := range []string{"v2.1.0", "v1.9.1", "2.1.0", "dev", "v1.9.1+dirty"} {
		if isPseudoVersion(v) {
			t.Errorf("%q is a real version and must be reported", v)
		}
	}
}
