// Package resilience provides connection resilience primitives for C2 profiles.
// DomainTracker manages per-domain health state, enabling intelligent failover
// that skips known-unhealthy endpoints and periodically attempts recovery.
package resilience

import (
	"sync"
	"time"
)

// domainState tracks health for a single domain/endpoint.
type domainState struct {
	failCount    int
	lastFailure  time.Time
	lastRecovery time.Time
	unhealthy    bool
}

// DomainTracker provides per-domain health tracking with periodic recovery.
// It is safe for concurrent use from multiple goroutines.
//
// Usage:
//   - Call RecordSuccess(idx) after a successful request to mark the domain healthy.
//   - Call RecordFailure(idx) after a failed request. Once consecutive failures
//     reach the threshold, the domain is marked unhealthy.
//   - Call IsAvailable(idx) before using a domain. Unhealthy domains return false
//     unless enough time has passed for a recovery attempt.
//   - Call FindNextAvailable(startIdx, count) to find the next healthy domain.
type DomainTracker struct {
	mu               sync.Mutex
	domains          []domainState
	threshold        int
	recoveryInterval time.Duration
}

// NewTracker creates a DomainTracker for the given number of domains.
// threshold: consecutive failures before a domain is marked unhealthy (default 5).
// recoverySeconds: seconds between recovery attempts for unhealthy domains (default 600).
// If domainCount <= 1, the tracker is a no-op (single domain is always available).
func NewTracker(domainCount, threshold, recoverySeconds int) *DomainTracker {
	if threshold <= 0 {
		threshold = 5
	}
	if recoverySeconds <= 0 {
		recoverySeconds = 600 // 10 minutes default
	}
	return &DomainTracker{
		domains:          make([]domainState, domainCount),
		threshold:        threshold,
		recoveryInterval: time.Duration(recoverySeconds) * time.Second,
	}
}

// IsAvailable returns true if the domain at idx is healthy or due for a recovery
// attempt. For single-domain setups, always returns true.
func (t *DomainTracker) IsAvailable(idx int) bool {
	if len(t.domains) <= 1 {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx < 0 || idx >= len(t.domains) {
		return true
	}
	d := &t.domains[idx]
	if !d.unhealthy {
		return true
	}
	// Allow recovery attempt if enough time has passed
	if time.Since(d.lastRecovery) >= t.recoveryInterval {
		d.lastRecovery = time.Now()
		return true
	}
	return false
}

// RecordSuccess marks the domain at idx as healthy and resets its failure count.
func (t *DomainTracker) RecordSuccess(idx int) {
	if len(t.domains) <= 1 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx < 0 || idx >= len(t.domains) {
		return
	}
	t.domains[idx].failCount = 0
	t.domains[idx].unhealthy = false
}

// RecordFailure increments the failure count for the domain at idx.
// Returns true if the domain was newly marked unhealthy (crossed the threshold).
func (t *DomainTracker) RecordFailure(idx int) bool {
	if len(t.domains) <= 1 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx < 0 || idx >= len(t.domains) {
		return false
	}
	d := &t.domains[idx]
	d.failCount++
	d.lastFailure = time.Now()
	if !d.unhealthy && d.failCount >= t.threshold {
		d.unhealthy = true
		d.lastRecovery = time.Now()
		return true
	}
	return false
}

// FindNextAvailable returns the index of the next available domain starting
// from startIdx (exclusive). Returns startIdx if no other domain is available
// (all unhealthy and not due for recovery).
func (t *DomainTracker) FindNextAvailable(startIdx, count int) int {
	if count <= 1 {
		return 0
	}
	for i := 1; i < count; i++ {
		candidate := (startIdx + i) % count
		if t.IsAvailable(candidate) {
			return candidate
		}
	}
	return startIdx // fallback: all unhealthy, try original
}

// HealthyCount returns the number of currently healthy domains.
func (t *DomainTracker) HealthyCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	healthy := 0
	for i := range t.domains {
		if !t.domains[i].unhealthy {
			healthy++
		}
	}
	return healthy
}

// AllUnhealthy returns true if every tracked domain is marked unhealthy.
func (t *DomainTracker) AllUnhealthy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.domains {
		if !t.domains[i].unhealthy {
			return false
		}
	}
	return len(t.domains) > 0
}

// Reset clears all health state, marking all domains as healthy.
func (t *DomainTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.domains {
		t.domains[i] = domainState{}
	}
}
