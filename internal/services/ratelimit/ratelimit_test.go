package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuckets(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	b := NewBuckets(10, 6*time.Second, func() time.Time { return now })
	for i := 0; i < 10; i++ {
		assert.True(t, b.Allow("a"), "burst %d", i)
	}
	assert.False(t, b.Allow("a"))
	assert.True(t, b.Allow("b"), "keys are independent")
	now = now.Add(6 * time.Second)
	assert.True(t, b.Allow("a"), "one more after 6s")
	assert.False(t, b.Allow("a"))
	now = now.Add(5 * time.Second)
	assert.False(t, b.Allow("a"))

	b.Forget("a")
	assert.True(t, b.Allow("a"))
	assert.Equal(t, 2, b.Len())
	now = now.Add(61 * time.Second)
	b.Sweep()
	assert.Equal(t, 0, b.Len())
	assert.NotNil(t, NewBuckets(1, time.Second, nil))
}

func TestWindow(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 59, 0, 0, time.UTC)
	w := NewWindow(3, time.Hour, func() time.Time { return now })
	for i := 1; i <= 3; i++ {
		n, ok := w.Add("x")
		assert.Equal(t, i, n)
		assert.True(t, ok)
	}
	n, ok := w.Add("x")
	assert.Equal(t, 4, n)
	assert.False(t, ok)
	assert.Equal(t, 4, w.Count("x"))
	assert.Equal(t, map[string]int{"x": 4}, w.Snapshot())
	assert.Equal(t, 3, w.Limit())

	now = now.Add(time.Minute) // next hour
	assert.Equal(t, 0, w.Count("x"))
	_, ok = w.Add("x")
	assert.True(t, ok)
	assert.NotNil(t, NewWindow(1, time.Hour, nil))
}
