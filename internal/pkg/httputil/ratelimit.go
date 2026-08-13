package httputil

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const defaultRateLimiterIdleTTL = 10 * time.Minute

type IPRateLimiter struct {
	mu          sync.Mutex
	limiters    map[string]*rate.Limiter
	lastSeen    map[string]time.Time
	lastCleanup time.Time
	idleTTL     time.Duration
	limit       rate.Limit
	burst       int
	keyFunc     func(*http.Request) string
}

func NewIPRateLimiter(limit rate.Limit, burst int) *IPRateLimiter {
	return NewIPRateLimiterWithIdleTTL(limit, burst, defaultRateLimiterIdleTTL)
}

func NewIPRateLimiterWithIdleTTL(limit rate.Limit, burst int, idleTTL time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		idleTTL:  idleTTL,
		limit:    limit,
		burst:    burst,
	}
}

func (l *IPRateLimiter) SetKeyFunc(f func(*http.Request) string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keyFunc = f
}

func (l *IPRateLimiter) key(r *http.Request) string {
	l.mu.Lock()
	kf := l.keyFunc
	l.mu.Unlock()
	if kf != nil {
		return kf(r)
	}
	return GetRemoteIP(r)
}

func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastCleanup) > l.idleTTL {
		l.evict(now)
	}

	limiter, ok := l.limiters[ip]
	if !ok {
		limiter = rate.NewLimiter(l.limit, l.burst)
		l.limiters[ip] = limiter
	}
	l.lastSeen[ip] = now
	return limiter.Allow()
}

func (l *IPRateLimiter) evict(now time.Time) {
	for ip, seen := range l.lastSeen {
		if now.Sub(seen) > l.idleTTL {
			delete(l.limiters, ip)
			delete(l.lastSeen, ip)
		}
	}
	l.lastCleanup = now
}

func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(l.key(r)) {
			RespondError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Too many requests, please try again later")
			return
		}
		next.ServeHTTP(w, r)
	})
}
