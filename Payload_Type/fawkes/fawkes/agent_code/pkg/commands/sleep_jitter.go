package commands

import (
	"math/rand"
	"time"
)

// CalculateAdaptiveSleep computes the sleep duration using the specified jitter profile.
func CalculateAdaptiveSleep(interval, jitter int, profile string) time.Duration {
	if jitter == 0 || interval <= 0 {
		if interval < 1 {
			interval = 1
		}
		return time.Duration(interval) * time.Second
	}

	switch profile {
	case "normal":
		return jitterNormal(interval, jitter)
	case "exponential":
		return jitterExponential(interval, jitter)
	default:
		return jitterUniform(interval, jitter)
	}
}

// jitterUniform applies uniform random jitter (existing Freyja-style behavior).
func jitterUniform(interval, jitter int) time.Duration {
	jitterFloat := float64(rand.Intn(jitter)) / 100.0
	jitterDiff := float64(interval) * jitterFloat

	actual := interval
	if rand.Intn(2) == 0 {
		actual += int(jitterDiff)
	} else {
		actual -= int(jitterDiff)
	}
	if actual < 1 {
		actual = 1
	}
	return time.Duration(actual) * time.Second
}

// jitterNormal applies Gaussian/normal distribution jitter centered on the interval.
// Most sleeps cluster near the interval with rare outliers — harder to fingerprint statistically.
func jitterNormal(interval, jitter int) time.Duration {
	maxVariance := float64(interval) * float64(jitter) / 100.0
	stddev := maxVariance / 3.0

	offset := rand.NormFloat64() * stddev
	actual := float64(interval) + offset

	minVal := float64(interval) - maxVariance
	maxVal := float64(interval) + maxVariance
	if actual < minVal {
		actual = minVal
	}
	if actual > maxVal {
		actual = maxVal
	}
	if actual < 1 {
		actual = 1
	}
	return time.Duration(actual * float64(time.Second))
}

// jitterExponential applies exponential distribution jitter biased toward shorter sleeps.
// Creates a "bursty" pattern with occasional long pauses — mimics human interaction patterns.
func jitterExponential(interval, jitter int) time.Duration {
	maxVariance := float64(interval) * float64(jitter) / 100.0
	lambda := 1.0 / (maxVariance / 2.0)

	sample := rand.ExpFloat64() / lambda

	if sample > maxVariance {
		sample = maxVariance
	}

	actual := float64(interval) - maxVariance/2.0 + sample
	if actual < 1 {
		actual = 1
	}
	return time.Duration(actual * float64(time.Second))
}

// ValidJitterProfile returns true if the profile name is recognized.
func ValidJitterProfile(profile string) bool {
	switch profile {
	case "", "uniform", "normal", "exponential":
		return true
	}
	return false
}

// JitterProfileDescription returns a human-readable description of the profile.
func JitterProfileDescription(profile string) string {
	switch profile {
	case "normal":
		return "normal (Gaussian bell curve — clusters near interval, rare outliers)"
	case "exponential":
		return "exponential (bursty — shorter sleeps with occasional long pauses)"
	default:
		return "uniform (flat random — legacy behavior)"
	}
}
