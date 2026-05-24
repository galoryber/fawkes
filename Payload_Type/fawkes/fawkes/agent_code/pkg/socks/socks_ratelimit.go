package socks

import (
	"sync"
	"time"
)

// RateLimiter implements a token-bucket rate limiter for per-connection
// bandwidth limiting. Each connection gets its own limiter that controls
// how many bytes can flow through per time window.
type RateLimiter struct {
	mu         sync.Mutex
	bytesPerSec int64 // 0 = unlimited
	tokens     int64
	maxBurst   int64
	lastRefill time.Time
}

// NewRateLimiter creates a rate limiter with the given bytes/sec limit.
// burstFactor controls how much burst is allowed (e.g., 2 = can burst to 2x rate).
// Pass bytesPerSec=0 for unlimited.
func NewRateLimiter(bytesPerSec int64, burstFactor int) *RateLimiter {
	if bytesPerSec <= 0 {
		return &RateLimiter{bytesPerSec: 0}
	}
	if burstFactor < 1 {
		burstFactor = 1
	}
	maxBurst := bytesPerSec * int64(burstFactor)
	return &RateLimiter{
		bytesPerSec: bytesPerSec,
		tokens:      maxBurst, // start full
		maxBurst:    maxBurst,
		lastRefill:  time.Now(),
	}
}

// Allow checks if n bytes can be sent and consumes tokens.
// Returns the number of bytes allowed (may be less than requested)
// and how long to wait before retrying if 0 bytes are allowed.
func (r *RateLimiter) Allow(n int) (allowed int, wait time.Duration) {
	if r.bytesPerSec == 0 {
		return n, 0 // unlimited
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(r.lastRefill)
	refill := int64(elapsed.Seconds() * float64(r.bytesPerSec))
	if refill > 0 {
		r.tokens += refill
		if r.tokens > r.maxBurst {
			r.tokens = r.maxBurst
		}
		r.lastRefill = now
	}

	if r.tokens <= 0 {
		// No tokens available — calculate wait time for at least 1 byte
		return 0, time.Duration(float64(time.Second) / float64(r.bytesPerSec))
	}

	// Allow up to available tokens
	allowed = n
	if int64(allowed) > r.tokens {
		allowed = int(r.tokens)
	}
	r.tokens -= int64(allowed)
	return allowed, 0
}

// WaitAndAllow blocks until n bytes (or a portion) can be sent.
// Returns the number of bytes allowed. Use in a loop for full consumption.
func (r *RateLimiter) WaitAndAllow(n int) int {
	for {
		allowed, wait := r.Allow(n)
		if allowed > 0 {
			return allowed
		}
		time.Sleep(wait)
	}
}

// SetRate updates the rate limit. Pass 0 to disable limiting.
func (r *RateLimiter) SetRate(bytesPerSec int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bytesPerSec = bytesPerSec
	if bytesPerSec <= 0 {
		r.bytesPerSec = 0
		return
	}
	r.maxBurst = bytesPerSec * 2
	if r.tokens > r.maxBurst {
		r.tokens = r.maxBurst
	}
}

// Rate returns the current bytes/sec limit (0 = unlimited).
func (r *RateLimiter) Rate() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytesPerSec
}

// BandwidthConfig holds bandwidth limiting configuration for the SOCKS proxy.
type BandwidthConfig struct {
	BytesPerSec int64 // global per-connection rate limit (0 = unlimited)
}

// perConnLimiters manages rate limiters for active connections.
type perConnLimiters struct {
	mu       sync.Mutex
	limiters map[uint32]*RateLimiter
	config   BandwidthConfig
}

func newPerConnLimiters() *perConnLimiters {
	return &perConnLimiters{
		limiters: make(map[uint32]*RateLimiter),
	}
}

// getOrCreate returns the rate limiter for a connection, creating one if needed.
func (p *perConnLimiters) getOrCreate(serverId uint32) *RateLimiter {
	p.mu.Lock()
	defer p.mu.Unlock()

	if rl, ok := p.limiters[serverId]; ok {
		return rl
	}

	rl := NewRateLimiter(p.config.BytesPerSec, 2)
	p.limiters[serverId] = rl
	return rl
}

// remove deletes the limiter for a closed connection.
func (p *perConnLimiters) remove(serverId uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.limiters, serverId)
}

// setConfig updates the bandwidth configuration. Existing connections
// keep their current rate until they're recreated.
func (p *perConnLimiters) setConfig(cfg BandwidthConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg
}

// getConfig returns the current bandwidth configuration.
func (p *perConnLimiters) getConfig() BandwidthConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.config
}
