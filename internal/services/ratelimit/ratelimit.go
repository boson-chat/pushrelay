// Package ratelimit holds the relay's in-memory limiters: per-key token
// buckets (pushes per mailbox) and fixed windows (pushes per install per
// hour, mailbox creations per IP per hour). The relay runs as a single
// replica; counters restart with the process (the per-mailbox daily cap
// is in the database).
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Buckets is a token bucket per key.
type Buckets struct {
	mu    sync.Mutex
	every time.Duration
	burst int
	now   func() time.Time
	m     map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewBuckets allows burst at once, then one per every.
func NewBuckets(burst int, every time.Duration, now func() time.Time) *Buckets {
	if now == nil {
		now = time.Now
	}
	return &Buckets{every: every, burst: burst, now: now, m: map[string]*bucket{}}
}

// Allow takes a token for key.
func (b *Buckets) Allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	e := b.m[key]
	if e == nil {
		e = &bucket{lim: rate.NewLimiter(rate.Every(b.every), b.burst)}
		b.m[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// Forget drops key (a deleted mailbox).
func (b *Buckets) Forget(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, key)
}

// Sweep drops buckets that refilled completely (idle long enough).
func (b *Buckets) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	full := b.every * time.Duration(b.burst)
	now := b.now()
	for k, e := range b.m {
		if now.Sub(e.seen) > full {
			delete(b.m, k)
		}
	}
}

// Len is the number of tracked keys.
func (b *Buckets) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}

// Window counts events per key in fixed windows (e.g. per clock hour).
type Window struct {
	mu    sync.Mutex
	size  time.Duration
	limit int
	now   func() time.Time
	start time.Time
	m     map[string]int
}

// NewWindow allows limit events per key per window of size.
func NewWindow(limit int, size time.Duration, now func() time.Time) *Window {
	if now == nil {
		now = time.Now
	}
	return &Window{size: size, limit: limit, now: now, m: map[string]int{}}
}

func (w *Window) roll() {
	if start := w.now().Truncate(w.size); !start.Equal(w.start) {
		w.start = start
		w.m = map[string]int{}
	}
}

// Add counts one event for key and reports the new count and whether it
// is within the limit. The first event above the limit has count == limit+1.
func (w *Window) Add(key string) (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.roll()
	w.m[key]++
	n := w.m[key]
	return n, n <= w.limit
}

// Count is key's count in the current window.
func (w *Window) Count(key string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.roll()
	return w.m[key]
}

// Snapshot copies the current window's counts.
func (w *Window) Snapshot() map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.roll()
	out := make(map[string]int, len(w.m))
	for k, v := range w.m {
		out[k] = v
	}
	return out
}

// Limit is the per-window limit.
func (w *Window) Limit() int { return w.limit }
