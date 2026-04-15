package resilience

import (
	"sync"
	"testing"
	"time"
)

func TestNewTracker_Defaults(t *testing.T) {
	tr := NewTracker(3, 0, 0)
	if len(tr.domains) != 3 {
		t.Fatalf("domains = %d, want 3", len(tr.domains))
	}
	if tr.threshold != 5 {
		t.Fatalf("threshold = %d, want 5 (default)", tr.threshold)
	}
	if tr.recoveryInterval != 600*time.Second {
		t.Fatalf("recoveryInterval = %v, want 600s", tr.recoveryInterval)
	}
}

func TestNewTracker_CustomValues(t *testing.T) {
	tr := NewTracker(5, 10, 120)
	if tr.threshold != 10 {
		t.Fatalf("threshold = %d, want 10", tr.threshold)
	}
	if tr.recoveryInterval != 120*time.Second {
		t.Fatalf("recoveryInterval = %v, want 120s", tr.recoveryInterval)
	}
}

func TestIsAvailable_SingleDomain(t *testing.T) {
	// Single domain is always available (no-op behavior)
	tr := NewTracker(1, 3, 600)
	if !tr.IsAvailable(0) {
		t.Fatal("single domain should always be available")
	}
	// Even after recording failures
	tr.RecordFailure(0)
	tr.RecordFailure(0)
	tr.RecordFailure(0)
	if !tr.IsAvailable(0) {
		t.Fatal("single domain should remain available even after failures")
	}
}

func TestIsAvailable_HealthyDomain(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	if !tr.IsAvailable(0) {
		t.Fatal("fresh domain should be available")
	}
	if !tr.IsAvailable(1) {
		t.Fatal("fresh domain should be available")
	}
	if !tr.IsAvailable(2) {
		t.Fatal("fresh domain should be available")
	}
}

func TestIsAvailable_OutOfRange(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	// Out of range should return true (defensive)
	if !tr.IsAvailable(-1) {
		t.Fatal("out of range should return true")
	}
	if !tr.IsAvailable(5) {
		t.Fatal("out of range should return true")
	}
}

func TestRecordFailure_BelowThreshold(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	if tr.RecordFailure(0) {
		t.Fatal("should not mark unhealthy before threshold")
	}
	if tr.RecordFailure(0) {
		t.Fatal("should not mark unhealthy before threshold")
	}
	if !tr.IsAvailable(0) {
		t.Fatal("domain should still be available below threshold")
	}
}

func TestRecordFailure_AtThreshold(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	tr.RecordFailure(0) // 1
	tr.RecordFailure(0) // 2
	if !tr.RecordFailure(0) { // 3 = threshold
		t.Fatal("should return true when newly marked unhealthy")
	}
	if tr.IsAvailable(0) {
		t.Fatal("domain should be unavailable after reaching threshold")
	}
}

func TestRecordFailure_AlreadyUnhealthy(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	tr.RecordFailure(0)
	tr.RecordFailure(0)
	tr.RecordFailure(0) // now unhealthy
	// Further failures should not return true again
	if tr.RecordFailure(0) {
		t.Fatal("should not return true for already-unhealthy domain")
	}
}

func TestRecordFailure_SingleDomainNoOp(t *testing.T) {
	tr := NewTracker(1, 3, 600)
	if tr.RecordFailure(0) {
		t.Fatal("single domain tracker should never mark unhealthy")
	}
}

func TestRecordSuccess_ResetsFailCount(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	tr.RecordFailure(0) // 1
	tr.RecordFailure(0) // 2
	tr.RecordSuccess(0) // reset
	tr.RecordFailure(0) // 1 again (after reset)
	tr.RecordFailure(0) // 2 again
	if !tr.IsAvailable(0) {
		t.Fatal("domain should be available (fail count was reset)")
	}
}

func TestRecordSuccess_RestoresUnhealthy(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	tr.RecordFailure(0)
	tr.RecordFailure(0)
	tr.RecordFailure(0) // unhealthy
	if tr.IsAvailable(0) {
		t.Fatal("should be unavailable")
	}
	tr.RecordSuccess(0) // restore
	if !tr.IsAvailable(0) {
		t.Fatal("domain should be available after successful recovery")
	}
}

func TestRecordSuccess_SingleDomainNoOp(t *testing.T) {
	tr := NewTracker(1, 3, 600)
	tr.RecordSuccess(0) // should not panic
}

func TestIsAvailable_RecoveryAttempt(t *testing.T) {
	// Use a very short recovery interval for testing
	tr := NewTracker(3, 2, 1)
	tr.RecordFailure(0)
	tr.RecordFailure(0) // unhealthy, lastRecovery = now

	if tr.IsAvailable(0) {
		t.Fatal("should be unavailable immediately after marking unhealthy")
	}

	// Wait for recovery interval to elapse
	time.Sleep(1100 * time.Millisecond)

	if !tr.IsAvailable(0) {
		t.Fatal("should be available for recovery attempt after interval")
	}

	// After a recovery attempt, should be unavailable again until next interval
	if tr.IsAvailable(0) {
		t.Fatal("should be unavailable again after recovery attempt (lastRecovery updated)")
	}
}

func TestFindNextAvailable_AllHealthy(t *testing.T) {
	tr := NewTracker(3, 3, 600)
	next := tr.FindNextAvailable(0, 3)
	if next != 1 {
		t.Fatalf("next = %d, want 1", next)
	}
}

func TestFindNextAvailable_SkipsUnhealthy(t *testing.T) {
	tr := NewTracker(4, 2, 600)
	// Mark domain 1 unhealthy
	tr.RecordFailure(1)
	tr.RecordFailure(1)

	next := tr.FindNextAvailable(0, 4) // start at 0, skip 1
	if next != 2 {
		t.Fatalf("next = %d, want 2 (skipping unhealthy 1)", next)
	}
}

func TestFindNextAvailable_WrapsAround(t *testing.T) {
	tr := NewTracker(3, 2, 600)
	// Mark domains 1 and 2 unhealthy
	tr.RecordFailure(1)
	tr.RecordFailure(1)
	tr.RecordFailure(2)
	tr.RecordFailure(2)

	next := tr.FindNextAvailable(0, 3) // only 0 is healthy, so wraps
	if next != 0 {
		t.Fatalf("next = %d, want 0 (only healthy domain)", next)
	}
}

func TestFindNextAvailable_AllUnhealthy(t *testing.T) {
	tr := NewTracker(3, 2, 600)
	// Mark all unhealthy
	for i := 0; i < 3; i++ {
		tr.RecordFailure(i)
		tr.RecordFailure(i)
	}

	// Should return startIdx as fallback
	next := tr.FindNextAvailable(1, 3)
	if next != 1 {
		t.Fatalf("next = %d, want 1 (fallback to start)", next)
	}
}

func TestFindNextAvailable_SingleDomain(t *testing.T) {
	tr := NewTracker(1, 3, 600)
	if tr.FindNextAvailable(0, 1) != 0 {
		t.Fatal("single domain should always return 0")
	}
}

func TestHealthyCount(t *testing.T) {
	tr := NewTracker(5, 2, 600)
	if tr.HealthyCount() != 5 {
		t.Fatalf("healthy = %d, want 5", tr.HealthyCount())
	}

	tr.RecordFailure(0)
	tr.RecordFailure(0) // unhealthy
	if tr.HealthyCount() != 4 {
		t.Fatalf("healthy = %d, want 4", tr.HealthyCount())
	}

	tr.RecordFailure(3)
	tr.RecordFailure(3) // unhealthy
	if tr.HealthyCount() != 3 {
		t.Fatalf("healthy = %d, want 3", tr.HealthyCount())
	}

	tr.RecordSuccess(0) // restore
	if tr.HealthyCount() != 4 {
		t.Fatalf("healthy = %d, want 4 after recovery", tr.HealthyCount())
	}
}

func TestAllUnhealthy(t *testing.T) {
	tr := NewTracker(3, 2, 600)
	if tr.AllUnhealthy() {
		t.Fatal("should not be all unhealthy initially")
	}

	for i := 0; i < 3; i++ {
		tr.RecordFailure(i)
		tr.RecordFailure(i)
	}
	if !tr.AllUnhealthy() {
		t.Fatal("should be all unhealthy")
	}

	tr.RecordSuccess(1)
	if tr.AllUnhealthy() {
		t.Fatal("should not be all unhealthy after recovery")
	}
}

func TestReset(t *testing.T) {
	tr := NewTracker(3, 2, 600)
	for i := 0; i < 3; i++ {
		tr.RecordFailure(i)
		tr.RecordFailure(i)
	}
	if tr.HealthyCount() != 0 {
		t.Fatal("all should be unhealthy before reset")
	}

	tr.Reset()
	if tr.HealthyCount() != 3 {
		t.Fatalf("all should be healthy after reset, got %d", tr.HealthyCount())
	}
}

func TestConcurrentAccess(t *testing.T) {
	tr := NewTracker(5, 3, 600)
	var wg sync.WaitGroup

	// Concurrent failures and successes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			idx := n % 5
			if n%3 == 0 {
				tr.RecordSuccess(idx)
			} else {
				tr.RecordFailure(idx)
			}
			tr.IsAvailable(idx)
			tr.FindNextAvailable(idx, 5)
		}(i)
	}
	wg.Wait()

	// Should not panic — race detector will catch issues
	_ = tr.HealthyCount()
	_ = tr.AllUnhealthy()
}

func TestMultipleDomainsIndependent(t *testing.T) {
	tr := NewTracker(3, 2, 600)

	// Only mark domain 1 unhealthy
	tr.RecordFailure(1)
	tr.RecordFailure(1)

	if !tr.IsAvailable(0) {
		t.Fatal("domain 0 should be available")
	}
	if tr.IsAvailable(1) {
		t.Fatal("domain 1 should be unavailable")
	}
	if !tr.IsAvailable(2) {
		t.Fatal("domain 2 should be available")
	}
}
