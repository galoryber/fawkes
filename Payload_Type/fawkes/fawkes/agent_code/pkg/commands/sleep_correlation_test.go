package commands

import (
	"math"
	"testing"
	"time"
)

func TestNewNetworkCorrelator_DefaultMin(t *testing.T) {
	nc := NewNetworkCorrelator(5) // below minimum
	if nc.maxSamples != 50 {
		t.Errorf("Expected maxSamples=50 for too-small input, got %d", nc.maxSamples)
	}
}

func TestNewNetworkCorrelator_Custom(t *testing.T) {
	nc := NewNetworkCorrelator(100)
	if nc.maxSamples != 100 {
		t.Errorf("Expected maxSamples=100, got %d", nc.maxSamples)
	}
}

func TestRecordSleep_And_SampleCount(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	if nc.SampleCount() != 0 {
		t.Errorf("Expected 0 samples, got %d", nc.SampleCount())
	}

	nc.RecordSleep(10 * time.Second)
	nc.RecordSleep(12 * time.Second)
	nc.RecordSleep(11 * time.Second)

	if nc.SampleCount() != 3 {
		t.Errorf("Expected 3 samples, got %d", nc.SampleCount())
	}
}

func TestRecordSleep_Cap(t *testing.T) {
	nc := NewNetworkCorrelator(10)
	for i := 0; i < 20; i++ {
		nc.RecordSleep(time.Duration(i+1) * time.Second)
	}
	if nc.SampleCount() != 10 {
		t.Errorf("Expected 10 samples (capped), got %d", nc.SampleCount())
	}
}

func TestStats_InsufficientData(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	mean, stddev, cv := nc.Stats()
	if mean != 0 || stddev != 0 || cv != 0 {
		t.Errorf("Expected all zeros with no data, got mean=%f stddev=%f cv=%f", mean, stddev, cv)
	}

	nc.RecordSleep(10 * time.Second)
	mean, stddev, cv = nc.Stats()
	if mean != 0 || stddev != 0 || cv != 0 {
		t.Errorf("Expected all zeros with 1 sample, got mean=%f stddev=%f cv=%f", mean, stddev, cv)
	}
}

func TestStats_UniformSamples(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// All identical samples → stddev=0, cv=0
	for i := 0; i < 10; i++ {
		nc.RecordSleep(10 * time.Second)
	}

	mean, stddev, cv := nc.Stats()
	if math.Abs(mean-10000) > 1 {
		t.Errorf("Expected mean ~10000ms, got %f", mean)
	}
	if stddev != 0 {
		t.Errorf("Expected stddev 0 for identical samples, got %f", stddev)
	}
	if cv != 0 {
		t.Errorf("Expected cv 0 for identical samples, got %f", cv)
	}
}

func TestStats_VariedSamples(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// 5s, 10s, 15s → mean=10s, stddev>0
	nc.RecordSleep(5 * time.Second)
	nc.RecordSleep(10 * time.Second)
	nc.RecordSleep(15 * time.Second)

	mean, stddev, cv := nc.Stats()
	if math.Abs(mean-10000) > 1 {
		t.Errorf("Expected mean ~10000ms, got %f", mean)
	}
	if stddev <= 0 {
		t.Errorf("Expected positive stddev, got %f", stddev)
	}
	if cv <= 0 {
		t.Errorf("Expected positive cv, got %f", cv)
	}
}

func TestSuggestJitter_InsufficientSamples(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	for i := 0; i < 5; i++ {
		nc.RecordSleep(10 * time.Second)
	}
	_, _, recommend := nc.SuggestJitter(10)
	if recommend {
		t.Error("Should not recommend with insufficient samples")
	}
}

func TestSuggestJitter_TooRegular(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// All identical → CV=0 → too regular
	for i := 0; i < 20; i++ {
		nc.RecordSleep(10 * time.Second)
	}
	suggested, reason, recommend := nc.SuggestJitter(10)
	if !recommend {
		t.Error("Should recommend for too-regular pattern")
	}
	if suggested <= 10 {
		t.Errorf("Should suggest higher jitter, got %d", suggested)
	}
	if reason == "" {
		t.Error("Reason should not be empty")
	}
}

func TestSuggestJitter_NormalRange(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// Create samples with CV around 0.2 (normal range)
	for i := 0; i < 20; i++ {
		base := 10000 + (i%5)*2000 // 10-18s range
		nc.RecordSleep(time.Duration(base) * time.Millisecond)
	}
	_, _, recommend := nc.SuggestJitter(20)
	if recommend {
		t.Error("Should not recommend change for normal CV range")
	}
}

func TestCorrelatedSleep_InsufficientData(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	base := 10 * time.Second
	result := nc.CorrelatedSleep(base)
	if result != base {
		t.Errorf("Expected base duration with no data, got %v", result)
	}
}

func TestCorrelatedSleep_WithData(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	for i := 0; i < 20; i++ {
		nc.RecordSleep(10 * time.Second)
	}

	base := 12 * time.Second
	result := nc.CorrelatedSleep(base)

	// Result should be between base and mean (blended)
	// 80% of 12s + 20% of 10s = 11.6s
	expected := 11600 * time.Millisecond
	tolerance := 100 * time.Millisecond
	diff := result - expected
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("Expected ~%v, got %v", expected, result)
	}
}

func TestCorrelatedSleep_MinimumBound(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	for i := 0; i < 20; i++ {
		nc.RecordSleep(500 * time.Millisecond)
	}

	// Very short base — should be clamped to minimum 1s
	result := nc.CorrelatedSleep(100 * time.Millisecond)
	if result < 1*time.Second {
		t.Errorf("Expected at least 1s minimum, got %v", result)
	}
}

// --- RecordCheckIn tests ---

func TestRecordCheckIn_FirstCall(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	nc.RecordCheckIn()
	if nc.CheckInCount() != 0 {
		t.Errorf("First call should not record an interval, got %d", nc.CheckInCount())
	}
}

func TestRecordCheckIn_SecondCall(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	nc.RecordCheckIn()
	time.Sleep(10 * time.Millisecond)
	nc.RecordCheckIn()
	if nc.CheckInCount() != 1 {
		t.Errorf("Expected 1 interval after 2 calls, got %d", nc.CheckInCount())
	}
}

func TestRecordCheckIn_MultipleCalls(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	for i := 0; i < 10; i++ {
		nc.RecordCheckIn()
	}
	if nc.CheckInCount() != 9 {
		t.Errorf("Expected 9 intervals after 10 calls, got %d", nc.CheckInCount())
	}
}

func TestCheckInStats_InsufficientData(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	mean, stddev, cv := nc.CheckInStats()
	if mean != 0 || stddev != 0 || cv != 0 {
		t.Errorf("Expected zeros with no data, got mean=%f stddev=%f cv=%f", mean, stddev, cv)
	}
}

func TestCheckInStats_WithData(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// Simulate check-ins with known intervals by injecting directly
	nc.mu.Lock()
	for i := 0; i < 20; i++ {
		nc.checkinSamples = append(nc.checkinSamples, 10000+int64(i*200))
	}
	nc.mu.Unlock()

	mean, stddev, cv := nc.CheckInStats()
	if mean < 10000 || mean > 14000 {
		t.Errorf("Expected mean ~11900, got %f", mean)
	}
	if stddev <= 0 {
		t.Errorf("Expected positive stddev, got %f", stddev)
	}
	if cv <= 0 {
		t.Errorf("Expected positive cv, got %f", cv)
	}
}

// --- AdaptSleep tests ---

func TestAdaptSleep_InsufficientSamples(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	base := 10 * time.Second
	result := nc.AdaptSleep(base)
	if result != base {
		t.Errorf("Expected base duration with insufficient samples, got %v vs %v", result, base)
	}
}

func TestAdaptSleep_TooRegular_IncreasesVariance(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// Inject perfectly uniform check-in intervals (CV=0) → should boost
	nc.mu.Lock()
	for i := 0; i < 20; i++ {
		nc.checkinSamples = append(nc.checkinSamples, 10000)
	}
	nc.mu.Unlock()

	base := 10 * time.Second
	boostSeen := false
	for i := 0; i < 50; i++ {
		result := nc.AdaptSleep(base)
		if result > base {
			boostSeen = true
			break
		}
	}
	if !boostSeen {
		t.Error("Expected AdaptSleep to boost sleep when CV=0 (too regular), but all results were <= base")
	}
}

func TestAdaptSleep_NormalRange_NoChange(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// Inject samples with CV ~0.2 (within target range 0.10-0.40)
	nc.mu.Lock()
	for i := 0; i < 20; i++ {
		base := int64(10000 + (i%5)*2000) // 10-18s range
		nc.checkinSamples = append(nc.checkinSamples, base)
	}
	nc.mu.Unlock()

	_, _, cv := nc.CheckInStats()
	if cv < 0.10 || cv > 0.40 {
		t.Skipf("Test samples have CV=%f outside expected range, skipping", cv)
	}

	base := 10 * time.Second
	result := nc.AdaptSleep(base)
	if result != base {
		t.Errorf("Expected no adjustment in normal CV range, got %v vs %v", result, base)
	}
}

func TestAdaptSleep_TooErratic_Dampens(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// Inject highly variable samples (CV > 0.5)
	nc.mu.Lock()
	for i := 0; i < 20; i++ {
		val := int64(5000 + (i%2)*20000) // alternates between 5s and 25s
		nc.checkinSamples = append(nc.checkinSamples, val)
	}
	nc.mu.Unlock()

	_, _, cv := nc.CheckInStats()
	if cv <= 0.40 {
		t.Skipf("Test samples have CV=%f not erratic enough, skipping", cv)
	}

	base := 10 * time.Second
	result := nc.AdaptSleep(base)
	if result >= base {
		t.Errorf("Expected dampened sleep when CV>0.40, got %v >= %v", result, base)
	}
	// Should not go below 50% of base
	minAllowed := 5 * time.Second
	if result < minAllowed {
		t.Errorf("Result %v below minimum bound %v", result, minAllowed)
	}
}

func TestAdaptSleep_BoundsEnforced(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	// Extreme: CV = 0, should boost but not exceed 200%
	nc.mu.Lock()
	for i := 0; i < 20; i++ {
		nc.checkinSamples = append(nc.checkinSamples, 10000)
	}
	nc.mu.Unlock()

	base := 10 * time.Second
	for i := 0; i < 100; i++ {
		result := nc.AdaptSleep(base)
		maxAllowed := 20 * time.Second
		if result > maxAllowed {
			t.Errorf("Result %v exceeds maximum bound %v", result, maxAllowed)
		}
		minAllowed := 5 * time.Second
		if result < minAllowed {
			t.Errorf("Result %v below minimum bound %v", result, minAllowed)
		}
	}
}

func TestAdaptSleep_MinimumOneSecond(t *testing.T) {
	nc := NewNetworkCorrelator(50)
	nc.mu.Lock()
	for i := 0; i < 20; i++ {
		nc.checkinSamples = append(nc.checkinSamples, 500)
	}
	nc.mu.Unlock()

	result := nc.AdaptSleep(500 * time.Millisecond)
	if result < 1*time.Second {
		t.Errorf("Expected at least 1s minimum, got %v", result)
	}
}
