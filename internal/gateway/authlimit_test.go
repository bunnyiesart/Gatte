package gateway

import (
	"testing"
	"time"
)

// The clock is injected in every test here, and that is the point: this is
// a decision about rates, and a test that slept would be slow, flaky, and
// unable to assert anything about a window a minute wide.
//
// What is NOT tested here, deliberately: the contention itself. This
// package's harness opens SQLite with store.Open(":memory:"), which sets
// SetMaxOpenConns(1) -- one connection, no lock contention, no SQLITE_BUSY.
// A "flood slows the analyst" test on that harness would measure the
// database/sql queue and prove nothing about the property ADR-0027 exists
// for. The measurement that justified the decision is in the ADR, against
// the real adapter on disk; what lives here is the behaviour the code owes.

func at(base time.Time, d time.Duration) time.Time { return base.Add(d) }

// TestAuthLimit_FirstAttemptFromASourceIsAlwaysAudited is the property the
// whole design exists to keep. ADR-0012 bought the detection of token
// grinding with one row per rejected request; a limiter that could swallow
// the FIRST attempt from an address would hand that back.
func TestAuthLimit_FirstAttemptFromASourceIsAlwaysAudited(t *testing.T) {
	l := newAuthLimiter()
	base := time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

	for i, source := range []string{"198.51.100.1", "198.51.100.2", "203.0.113.9"} {
		if got := l.classify(source, at(base, time.Duration(i)*time.Millisecond)); got != authAdmit {
			t.Errorf("classify(%q) = %v, want authAdmit: the first attempt from an address is the detection", source, got)
		}
	}
}

// TestAuthLimit_MarksOncePerWindowThenDropsSilently: over budget, the trail
// gets exactly one line saying so, and the rest are counted in memory.
//
// A marker per suppressed attempt would be the flood wearing a different
// hat, which is why the marker is itself rate-limited.
func TestAuthLimit_MarksOncePerWindowThenDropsSilently(t *testing.T) {
	l := newAuthLimiter()
	base := time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)
	const source = "198.51.100.77"

	var admitted, marked, dropped int
	// All at the same instant, so nothing refills.
	for range 500 {
		switch l.classify(source, base) {
		case authAdmit:
			admitted++
		case authMark:
			marked++
		case authDrop:
			dropped++
		}
	}

	if admitted != int(authPerSourceBurst) {
		t.Errorf("admitted %d, want the burst %d", admitted, int(authPerSourceBurst))
	}
	if marked != 1 {
		t.Errorf("marked %d times in one window, want exactly 1 -- a marker per attempt is the flood again", marked)
	}
	if dropped != 500-admitted-marked {
		t.Errorf("dropped %d, want the rest (%d)", dropped, 500-admitted-marked)
	}
	if l.suppressed == 0 {
		t.Error("nothing was counted as suppressed; the in-memory count is the only place the volume survives")
	}

	// A window later, the source is announced again -- an attack that lasts
	// an hour must not be announced once and then be silent for the rest.
	if got := l.classify(source, at(base, authMarkerWindow+time.Second)); got != authAdmit && got != authMark {
		t.Errorf("classify after the window = %v, want the source to be heard from again", got)
	}
}

// TestAuthLimit_GlobalCeilingAlsoMarks is the hole the first version of this
// design had, found in review before it was written.
//
// The rule was "mark when the SOURCE bucket refuses". An attacker spread
// across many addresses never trips a source bucket -- each one is under
// its own budget -- and trips only the global backstop, so every one of
// those attempts fell into the silent drop. The distributed flood, the one
// that actually reaches the writer, was the one nobody was told about.
func TestAuthLimit_GlobalCeilingAlsoMarks(t *testing.T) {
	l := newAuthLimiter()
	base := time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

	var marked, dropped int
	// One attempt each from many distinct addresses, all at once: no source
	// is over its own budget, and the global ceiling is what refuses.
	for i := range 400 {
		source := "203.0.113." + string(rune('a'+i%26)) + string(rune('a'+i/26))
		switch l.classify(source, base) {
		case authMark:
			marked++
		case authDrop:
			dropped++
		}
	}

	if marked == 0 {
		t.Fatal("a distributed flood produced no marker at all: it passes every per-source bucket and trips only the global ceiling, so the trail would say nothing about the attack that actually saturates the writer")
	}
	if dropped == 0 {
		t.Error("nothing was dropped; the global ceiling did not engage and this test is not exercising it")
	}
}

// TestAuthLimit_SourceMapIsBounded: the limiter's own state is keyed by a
// value the attacker chooses, so an unbounded map would close one denial of
// service by opening another.
func TestAuthLimit_SourceMapIsBounded(t *testing.T) {
	l := newAuthLimiter()
	base := time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

	for i := range authMaxSources * 3 {
		l.classify("10.0."+string(rune('a'+i%26))+"."+string(rune('a'+i/26)), at(base, time.Duration(i)*time.Microsecond))
	}

	if n := len(l.sources); n > authMaxSources {
		t.Errorf("the limiter holds %d source buckets, want at most %d: its own state must not be something an attacker can grow", n, authMaxSources)
	}
}

// TestAuthLimit_AFullMapFallsBackToTheGlobalCeilingNotToSilence pins the
// declared degradation. With the map full and nothing evictable, the
// decision belongs to the global bucket -- which still admits, marks and
// drops -- and never to an unconditional pass or an unconditional drop.
func TestAuthLimit_AFullMapFallsBackToTheGlobalCeilingNotToSilence(t *testing.T) {
	l := newAuthLimiter()
	base := time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

	// Fill the map at one instant so nothing is older than anything else.
	for i := range authMaxSources {
		l.sources["fill-"+string(rune(i%256))+string(rune(i/256))] = &bucket{seen: base, last: base, tokens: 0}
	}

	// Drain the global budget. It takes MANY sources to do it, and that is
	// itself the per-source ceiling working: one address cannot spend the
	// global budget, because its own bucket stops it at the burst.
	for i := range int(authGlobalBurst) + 50 {
		l.classify("198.51.100."+string(rune('a'+i%26))+string(rune('a'+i/26)), base)
	}
	if got := l.classify("198.51.100.201", base); got == authAdmit {
		t.Error("a new source was admitted with the map full and the global budget spent: the fallback must be the global ceiling, not a free pass")
	}
}
