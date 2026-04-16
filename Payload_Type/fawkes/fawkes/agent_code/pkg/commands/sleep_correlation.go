package commands

import (
	"math"
	"sync"
	"time"
)

// NetworkCorrelator tracks actual callback timing patterns and adjusts sleep
// intervals to avoid statistical anomaly detection. It builds a histogram of
// recent sleep durations and can suggest timing that blends with observed patterns.
type NetworkCorrelator struct {
	mu       sync.Mutex
	samples  []int64 // recent sleep durations in milliseconds
	maxSamples int
}

// NewNetworkCorrelator creates a correlator that tracks the last N samples.
func NewNetworkCorrelator(maxSamples int) *NetworkCorrelator {
	if maxSamples < 10 {
		maxSamples = 50
	}
	return &NetworkCorrelator{
		samples:    make([]int64, 0, maxSamples),
		maxSamples: maxSamples,
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

// Stats returns mean, stddev, and coefficient of variation (CV) of recorded samples.
// CV < 0.1 means very regular (suspicious), CV > 0.3 means good variation.
func (nc *NetworkCorrelator) Stats() (mean, stddev, cv float64) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	n := len(nc.samples)
	if n < 2 {
		return 0, 0, 0
	}

	// Mean
	var sum float64
	for _, s := range nc.samples {
		sum += float64(s)
	}
	mean = sum / float64(n)

	// Standard deviation
	var sumSq float64
	for _, s := range nc.samples {
		diff := float64(s) - mean
		sumSq += diff * diff
	}
	stddev = math.Sqrt(sumSq / float64(n-1))

	// Coefficient of variation
	if mean > 0 {
		cv = stddev / mean
	}
	return mean, stddev, cv
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

// CorrelatedSleep calculates a sleep duration that factors in the timing histogram.
// If correlation has enough data, it slightly biases the sleep toward the observed
// mean to maintain a more natural-looking pattern.
func (nc *NetworkCorrelator) CorrelatedSleep(baseDuration time.Duration) time.Duration {
	mean, _, _ := nc.Stats()
	n := nc.SampleCount()

	if n < 10 || mean == 0 {
		return baseDuration
	}

	// Blend: 80% base duration (from jitter profile) + 20% toward observed mean.
	// This keeps the jitter profile's distribution shape while slightly
	// anchoring to the actual pattern, reducing statistical outliers.
	baseMs := float64(baseDuration.Milliseconds())
	blended := baseMs*0.8 + mean*0.2

	if blended < 1000 {
		blended = 1000 // minimum 1 second
	}

	return time.Duration(blended) * time.Millisecond
}
