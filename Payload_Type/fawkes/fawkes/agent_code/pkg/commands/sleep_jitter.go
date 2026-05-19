package commands

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

var (
	instanceDrift     float64
	instanceDriftOnce sync.Once
)

func initInstanceDrift() {
	instanceDriftOnce.Do(func() {
		var b [8]byte
		_, _ = rand.Read(b[:])
		instanceDrift = (float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64)) * 0.1
	})
}

func cryptoFloat64() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}

func cryptoIntn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(cryptoFloat64() * float64(n))
}

func cryptoNormFloat64() float64 {
	u1 := cryptoFloat64()
	u2 := cryptoFloat64()
	if u1 < 1e-15 {
		u1 = 1e-15
	}
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func cryptoExpFloat64() float64 {
	u := cryptoFloat64()
	if u < 1e-15 {
		u = 1e-15
	}
	return -math.Log(u)
}

// CalculateAdaptiveSleep computes the sleep duration using the specified jitter profile.
// Uses crypto/rand for all randomness and returns millisecond-precision durations.
func CalculateAdaptiveSleep(interval, jitter int, profile string) time.Duration {
	initInstanceDrift()

	if jitter == 0 || interval <= 0 {
		if interval < 1 {
			interval = 1
		}
		drifted := float64(interval) * (1.0 + instanceDrift - 0.05)
		if drifted < 1.0 {
			drifted = 1.0
		}
		return time.Duration(drifted * float64(time.Second))
	}

	var base time.Duration
	switch profile {
	case "normal":
		base = jitterNormal(interval, jitter)
	case "exponential":
		base = jitterExponential(interval, jitter)
	default:
		base = jitterUniform(interval, jitter)
	}

	baseMs := float64(base.Milliseconds())
	driftedMs := baseMs * (1.0 + instanceDrift - 0.05)
	microJitter := (cryptoFloat64() - 0.5) * 200
	driftedMs += microJitter

	if driftedMs < 1000 {
		driftedMs = 1000
	}
	return time.Duration(driftedMs) * time.Millisecond
}

func jitterUniform(interval, jitter int) time.Duration {
	jitterFloat := cryptoFloat64() * float64(jitter) / 100.0
	jitterDiff := float64(interval) * jitterFloat

	actual := float64(interval)
	if cryptoIntn(2) == 0 {
		actual += jitterDiff
	} else {
		actual -= jitterDiff
	}
	if actual < 1 {
		actual = 1
	}
	return time.Duration(actual * float64(time.Second))
}

func jitterNormal(interval, jitter int) time.Duration {
	maxVariance := float64(interval) * float64(jitter) / 100.0
	stddev := maxVariance / 3.0

	offset := cryptoNormFloat64() * stddev
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

func jitterExponential(interval, jitter int) time.Duration {
	maxVariance := float64(interval) * float64(jitter) / 100.0
	lambda := 1.0 / (maxVariance / 2.0)

	sample := cryptoExpFloat64() / lambda

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
