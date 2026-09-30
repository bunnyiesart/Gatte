package httpapi

// Which tools each subject has been LISTED (design/adr/0042 item 2).
//
// The handler is stateless (every POST builds its own mcp.Server), and a
// client reads tools/list once, at connect. So when a tool is pulled from
// a caller mid-session -- a role change, a rewrite now awaiting review, a
// deregistered backend -- the model still holds it and calls it, and gets
// the SDK's `unknown tool`, which reads as "wrong name, try another". This
// memory is what lets the answer say "no longer available to you" instead,
// and it is shaped so that it can say nothing else:
//
//   - it is keyed by the verified subject, and only a tools/list answered
//     to that subject writes to it, with exactly the names that list
//     carried -- so it never learns a name the subject was not shown;
//   - the answer it enables is one constant text for every cause, and only
//     for a name in that subject's own memory; a name they were never
//     listed still gets the SDK's bytes (no oracle for guessed names);
//   - it lives in this process only, for listedRetention, bounded in
//     subjects; after a restart or past the retention a pulled tool is
//     `unknown tool` again, as before -- a declared limit, not a leak.

import (
	"sync"
	"time"
)

const (
	// listedRetention is how long a listing is remembered: longer than an
	// analyst's working week, so a session left open over days is covered.
	listedRetention = 7 * 24 * time.Hour
	// listedMaxSubjects bounds the memory; past it the subject listed
	// longest ago is forgotten first.
	listedMaxSubjects = 4096
)

type listedTools struct {
	mu        sync.Mutex
	bySubject map[string]*subjectListing
}

type subjectListing struct {
	names map[string]time.Time
	last  time.Time
}

func newListedTools() *listedTools {
	return &listedTools{bySubject: map[string]*subjectListing{}}
}

// remember records that subject was just listed names.
func (l *listedTools) remember(subject string, names []string, now time.Time) {
	if subject == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.bySubject[subject]
	if !ok {
		if len(l.bySubject) >= listedMaxSubjects {
			l.evictOldest()
		}
		s = &subjectListing{names: map[string]time.Time{}}
		l.bySubject[subject] = s
	}
	s.last = now
	for n, at := range s.names {
		if now.Sub(at) > listedRetention {
			delete(s.names, n)
		}
	}
	for _, n := range names {
		s.names[n] = now
	}
}

// wasListed reports whether subject was listed name within the retention.
func (l *listedTools) wasListed(subject, name string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.bySubject[subject]
	if !ok {
		return false
	}
	at, ok := s.names[name]
	return ok && now.Sub(at) <= listedRetention
}

func (l *listedTools) evictOldest() {
	var (
		oldest string
		when   time.Time
	)
	for subject, s := range l.bySubject {
		if oldest == "" || s.last.Before(when) {
			oldest, when = subject, s.last
		}
	}
	delete(l.bySubject, oldest)
}
