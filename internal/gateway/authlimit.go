package gateway

import "time"

// Rate-limiting constants for the audit of authentication failures
// (design/adr/0027-limite-de-taxa-na-auditoria-de-falha-de-autenticacao.md).
//
// Constants and not configuration keys, deliberately. These came out of one
// measurement against one fleet of seven analysts, not out of an operator's
// preference: 100 rejected requests a second cost the analyst's own audit
// write p95 2.06 ms against 1.29 ms idle, so 50/s leaves half an order of
// magnitude of headroom. Turning them into TOML would be four more things
// to operate, four more ways to be wrong at 03:00, and a wider surface for
// ADR-0009 to carry -- for numbers nobody outside this file can calibrate
// without repeating the measurement.
//
// Changing them is a diff somebody reviews, which is the same posture
// MinResultBytes takes.
const (
	// authPerSourceRate and authPerSourceBurst bound one source address.
	// The burst is what lets an ordinary misconfiguration -- a client with
	// a stale token retrying -- be recorded in full before anything is
	// suppressed.
	authPerSourceRate  = 5.0
	authPerSourceBurst = 20.0

	// authGlobalRate and authGlobalBurst are the backstop, and they are the
	// actual security property: unlike the per-source buckets, they do not
	// depend on how many distinct addresses an attacker can present.
	authGlobalRate  = 50.0
	authGlobalBurst = 200.0

	// authMarkerWindow is how often ONE line is written for a source that
	// is over its budget. The marker is itself rate-limited, because a
	// marker per suppressed attempt would be the flood wearing a different
	// hat.
	authMarkerWindow = time.Minute

	// authMaxSources bounds the map. A limiter whose state the attacker can
	// grow closes one denial of service by opening another.
	authMaxSources = 1024
)

// authVerdict is what the limiter says about one rejected request.
type authVerdict int

const (
	// authAdmit: write the record, exactly as before the limiter existed.
	authAdmit authVerdict = iota
	// authMark: write ONE record saying this source is over its budget.
	// This is what keeps suppression from being silent, and it is the
	// difference between a trail that says "an attack is happening" and one
	// that says nothing at all.
	authMark
	// authDrop: count it in memory and write nothing durable. The
	// operational log line still happens, at every attempt, unlimited --
	// see RecordAuthFailure.
	authDrop
)

// bucket is one token bucket plus the last time a marker was written for
// it.
type bucket struct {
	tokens float64
	last   time.Time
	marker time.Time
	// seen is the last time this bucket was touched at all, used to pick a
	// victim when the map is full.
	seen time.Time
}

// take consumes a token if one is available, refilling from elapsed time.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	} else {
		b.tokens = burst
	}
	b.last, b.seen = now, now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// authLimiter decides which authentication failures reach the durable
// trail. It is not safe for concurrent use on its own; the Gateway holds it
// under mu.
//
// # Why a per-source bucket AND a global one
//
// Per-source first, for fairness: one noisy address must not eat the budget
// that would have recorded a different attacker. Global second, because it
// is the part that actually bounds the writer -- an attacker choosing
// source addresses freely defeats any per-source scheme, and this one is
// keyed by a value the attacker picks.
type authLimiter struct {
	sources map[string]*bucket
	global  bucket
	// globalMarker is the last time a marker was written for the global
	// ceiling, kept separately so that the global backstop can announce
	// itself even when no single source is over its own budget -- the
	// distributed case, which the first version of this design dropped
	// silently.
	globalMarker time.Time
	// suppressed counts attempts that produced no durable record. In
	// memory, per process, and deliberately NOT in the heartbeat: ADR-0021
	// item 4 defines those counters as rows written, and a counter of rows
	// NOT written would falsify it (and bump the sink's schema version for
	// a number the trail already implies).
	suppressed uint64
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{sources: make(map[string]*bucket, 16)}
}

// classify decides what to do with one rejected request from source.
func (l *authLimiter) classify(source string, now time.Time) authVerdict {
	sourceOK := l.sourceAllows(source, now)
	if sourceOK && l.global.take(now, authGlobalRate, authGlobalBurst) {
		return authAdmit
	}

	// Over budget. WHICH ceiling refused decides which marker is consulted,
	// and conflating the two was the first version's bug: asking the source
	// marker first meant every brand-new address marked (its marker is
	// zero), so a flood spread over hundreds of addresses produced hundreds
	// of "rate-limited" lines -- the flood again, wearing the name of the
	// control that was supposed to bound it.
	//
	// Refused by its own bucket -> the source is the story, one line per
	// source per window. Refused only by the global backstop -> the source
	// is unremarkable and the CEILING is the story, one line per window for
	// all of them, which is the distributed case.
	var marked bool
	if !sourceOK {
		marked = l.markSource(source, now)
	} else {
		marked = l.markGlobal(now)
	}
	if marked {
		return authMark
	}
	l.suppressed++
	return authDrop
}

// sourceAllows consumes a token from source's bucket, creating it if
// needed. A full map degrades to the global ceiling alone -- never to
// silence.
func (l *authLimiter) sourceAllows(source string, now time.Time) bool {
	b, ok := l.sources[source]
	if !ok {
		if len(l.sources) >= authMaxSources {
			l.evict(now)
		}
		if len(l.sources) >= authMaxSources {
			// Still full: nothing to evict that is older than this. The
			// global bucket decides, which is the declared degradation.
			return true
		}
		b = &bucket{}
		l.sources[source] = b
	}
	return b.take(now, authPerSourceRate, authPerSourceBurst)
}

// evict drops the least recently seen of a small sample. Sampling rather
// than scanning: the map is bounded, the victim only has to be old, and a
// full scan on every insertion is work an attacker would be choosing for
// us.
func (l *authLimiter) evict(now time.Time) {
	const sample = 8
	var victim string
	var oldest time.Time
	n := 0
	for source, b := range l.sources {
		if n == 0 || b.seen.Before(oldest) {
			victim, oldest = source, b.seen
		}
		if n++; n >= sample {
			break
		}
	}
	if victim != "" {
		delete(l.sources, victim)
	}
}

// markSource reports whether this refusal should be the source's one line
// for the window. A bucket that has never marked is eligible -- it has just
// gone over budget for the first time, which is precisely the event worth a
// line.
func (l *authLimiter) markSource(source string, now time.Time) bool {
	b, ok := l.sources[source]
	if !ok {
		// No bucket means the map was full when this source appeared, so
		// the global ceiling owns this decision, not the source marker.
		return false
	}
	if !b.marker.IsZero() && now.Sub(b.marker) < authMarkerWindow {
		return false
	}
	b.marker = now
	return true
}

func (l *authLimiter) markGlobal(now time.Time) bool {
	if !l.globalMarker.IsZero() && now.Sub(l.globalMarker) < authMarkerWindow {
		return false
	}
	l.globalMarker = now
	return true
}
