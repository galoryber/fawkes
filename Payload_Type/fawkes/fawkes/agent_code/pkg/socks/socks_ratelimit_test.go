package socks

import (
	"testing"
	"time"
)

// --- RateLimiter Tests ---

func TestRateLimiter_Unlimited(t *testing.T) {
	rl := NewRateLimiter(0, 2)

	allowed, wait := rl.Allow(1000000)
	if allowed != 1000000 {
		t.Errorf("Unlimited limiter should allow all bytes, got %d", allowed)
	}
	if wait != 0 {
		t.Errorf("Unlimited limiter should have no wait, got %v", wait)
	}
}

func TestRateLimiter_LimitedBurst(t *testing.T) {
	// 1KB/s with 2x burst = 2KB max burst
	rl := NewRateLimiter(1024, 2)

	// First call should get up to burst (2048 bytes)
	allowed, wait := rl.Allow(4096)
	if allowed != 2048 {
		t.Errorf("Expected 2048 bytes (burst), got %d", allowed)
	}
	if wait != 0 {
		t.Errorf("First call should have no wait, got %v", wait)
	}

	// Second immediate call should get 0 (tokens exhausted)
	allowed2, wait2 := rl.Allow(1024)
	if allowed2 != 0 {
		t.Errorf("Expected 0 bytes (tokens exhausted), got %d", allowed2)
	}
	if wait2 == 0 {
		t.Error("Should have non-zero wait when tokens exhausted")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	rl := NewRateLimiter(10000, 1) // 10KB/s

	// Exhaust all tokens
	rl.Allow(10000)

	// Wait 100ms, should refill ~1000 bytes
	time.Sleep(110 * time.Millisecond)

	allowed, _ := rl.Allow(5000)
	if allowed < 800 || allowed > 1500 {
		t.Errorf("After 100ms at 10KB/s, expected ~1000 bytes, got %d", allowed)
	}
}

func TestRateLimiter_WaitAndAllow(t *testing.T) {
	// Use a very slow rate to force a meaningful wait
	rl := NewRateLimiter(100, 1) // 100 bytes/sec, burst = 100

	// Exhaust all tokens
	rl.Allow(100)

	// WaitAndAllow should block until tokens refill
	// At 100 bytes/sec, wait for 1 byte = 10ms. We request 50 bytes.
	start := time.Now()
	allowed := rl.WaitAndAllow(50)
	elapsed := time.Since(start)

	if allowed == 0 {
		t.Error("WaitAndAllow should return > 0 bytes")
	}
	// At 100 bytes/sec, need at least ~10ms to get even 1 byte
	if elapsed < 5*time.Millisecond {
		t.Errorf("WaitAndAllow should have waited (at 100 B/s), waited only %v", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("WaitAndAllow took too long: %v", elapsed)
	}
}

func TestRateLimiter_SetRate(t *testing.T) {
	rl := NewRateLimiter(1024, 2)

	if rl.Rate() != 1024 {
		t.Errorf("Expected rate 1024, got %d", rl.Rate())
	}

	rl.SetRate(2048)
	if rl.Rate() != 2048 {
		t.Errorf("Expected rate 2048 after SetRate, got %d", rl.Rate())
	}

	rl.SetRate(0)
	if rl.Rate() != 0 {
		t.Errorf("Expected rate 0 (unlimited) after SetRate(0), got %d", rl.Rate())
	}

	// Verify unlimited allows everything
	allowed, _ := rl.Allow(1000000)
	if allowed != 1000000 {
		t.Errorf("After SetRate(0), should allow all bytes, got %d", allowed)
	}
}

func TestRateLimiter_NegativeRate(t *testing.T) {
	rl := NewRateLimiter(-100, 2)

	// Negative rate should be treated as unlimited
	allowed, wait := rl.Allow(5000)
	if allowed != 5000 {
		t.Errorf("Negative rate should be unlimited, got %d allowed", allowed)
	}
	if wait != 0 {
		t.Errorf("Negative rate should have no wait, got %v", wait)
	}
}

func TestRateLimiter_ZeroBurstFactor(t *testing.T) {
	rl := NewRateLimiter(1024, 0)

	// burstFactor 0 should be treated as 1
	allowed, _ := rl.Allow(2048)
	if allowed != 1024 {
		t.Errorf("With burstFactor 0 (clamped to 1), expected 1024, got %d", allowed)
	}
}

// --- perConnLimiters Tests ---

func TestPerConnLimiters_GetOrCreate(t *testing.T) {
	p := newPerConnLimiters()
	p.setConfig(BandwidthConfig{BytesPerSec: 1024})

	rl1 := p.getOrCreate(1)
	rl2 := p.getOrCreate(1)

	if rl1 != rl2 {
		t.Error("getOrCreate should return same limiter for same serverId")
	}

	rl3 := p.getOrCreate(2)
	if rl1 == rl3 {
		t.Error("Different serverIds should get different limiters")
	}
}

func TestPerConnLimiters_Remove(t *testing.T) {
	p := newPerConnLimiters()
	p.setConfig(BandwidthConfig{BytesPerSec: 1024})

	rl1 := p.getOrCreate(1)
	p.remove(1)
	rl2 := p.getOrCreate(1)

	if rl1 == rl2 {
		t.Error("After remove, getOrCreate should create a new limiter")
	}
}

func TestPerConnLimiters_UnlimitedDefault(t *testing.T) {
	p := newPerConnLimiters()
	// Default config has BytesPerSec=0

	rl := p.getOrCreate(1)
	allowed, _ := rl.Allow(1000000)
	if allowed != 1000000 {
		t.Errorf("Default config should be unlimited, got %d allowed", allowed)
	}
}

func TestPerConnLimiters_ConfigChange(t *testing.T) {
	p := newPerConnLimiters()

	cfg := p.getConfig()
	if cfg.BytesPerSec != 0 {
		t.Errorf("Default config should be 0 (unlimited), got %d", cfg.BytesPerSec)
	}

	p.setConfig(BandwidthConfig{BytesPerSec: 2048})
	cfg2 := p.getConfig()
	if cfg2.BytesPerSec != 2048 {
		t.Errorf("Expected 2048 after setConfig, got %d", cfg2.BytesPerSec)
	}
}

// --- Manager Bandwidth Integration Tests ---

func TestManager_SetBandwidthLimit(t *testing.T) {
	m := NewManager()
	defer m.Close()

	m.SetBandwidthLimit(5120)
	if m.GetBandwidthLimit() != 5120 {
		t.Errorf("Expected 5120 bytes/sec, got %d", m.GetBandwidthLimit())
	}

	m.SetBandwidthLimit(0)
	if m.GetBandwidthLimit() != 0 {
		t.Errorf("Expected 0 (unlimited), got %d", m.GetBandwidthLimit())
	}
}
