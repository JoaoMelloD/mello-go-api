package security

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]rateBucket
}

type rateBucket struct {
	count     int
	resetTime time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]rateBucket),
	}
}

func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	if bucket.resetTime.IsZero() || now.After(bucket.resetTime) {
		l.buckets[key] = rateBucket{
			count:     1,
			resetTime: now.Add(l.window),
		}
		return true, 0
	}

	if bucket.count >= l.limit {
		return false, time.Until(bucket.resetTime)
	}

	bucket.count++
	l.buckets[key] = bucket
	return true, 0
}
