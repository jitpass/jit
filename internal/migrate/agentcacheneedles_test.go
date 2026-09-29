// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

// perNeedleSpans is the search needleIndex replaced: a bytes.Index per
// needle, resuming after each hit, then first-claim-wins in needle order.
// The one-pass index must return exactly what it did.
func perNeedleSpans(data []byte, needles []AgentCacheSecret) []agentSpan {
	var spans []agentSpan
	claimed := func(lo, hi int) bool {
		for _, s := range spans {
			if lo < s.end && s.start < hi {
				return true
			}
		}
		return false
	}
	for _, n := range needles {
		nb := []byte(n.Value)
		for off := 0; ; {
			i := bytes.Index(data[off:], nb)
			if i < 0 {
				break
			}
			lo := off + i
			hi := lo + len(nb)
			if !claimed(lo, hi) {
				spans = append(spans, agentSpan{start: lo, end: hi, varName: n.Var})
			}
			off = hi
		}
	}
	sort.Slice(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
	return spans
}

// Needles that share first bytes, contain each other, overlap themselves
// ("abab…"), and sit at the very end of the data: every case where one
// pass could disagree with a search per needle.
func TestNeedleIndexFindsWhatAPerNeedleSearchFound(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for round := 0; round < 300; round++ {
		alpha := "ab"
		if round%3 == 0 {
			alpha = "abc_"
		}
		word := func(n int) string {
			b := make([]byte, n)
			for i := range b {
				b[i] = alpha[r.Intn(len(alpha))]
			}
			return string(b)
		}
		var needles []AgentCacheSecret
		for k := 0; k < 1+r.Intn(6); k++ {
			needles = append(needles, AgentCacheSecret{Var: string(rune('A' + k)), Value: word(2 + r.Intn(6))})
		}
		sort.SliceStable(needles, func(a, b int) bool { return len(needles[a].Value) > len(needles[b].Value) })
		data := []byte(word(r.Intn(200)) + needles[0].Value)
		want := perNeedleSpans(data, needles)
		got := newNeedleIndex(needles).spans(data)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d, needles %+v, data %q:\n got %+v\nwant %+v", round, needles, data, got, want)
		}
	}
}
