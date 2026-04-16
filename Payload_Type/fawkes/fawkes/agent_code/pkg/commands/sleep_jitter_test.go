package commands

import (
	"math"
	"testing"
	"time"
)

func TestCalculateAdaptiveSleep_NoJitter(t *testing.T) {
	d := CalculateAdaptiveSleep(10, 0, "uniform")
	if d != 10*time.Second {
		t.Errorf("Expected 10s with 0 jitter, got %v", d)
	}
}

func TestCalculateAdaptiveSleep_ZeroInterval(t *testing.T) {
	d := CalculateAdaptiveSleep(0, 50, "uniform")
	if d < 1*time.Second {
		t.Errorf("Expected minimum 1s, got %v", d)
	}
}

func TestJitterUniform_Range(t *testing.T) {
	interval := 10
	jitter := 50

	for i := 0; i < 100; i++ {
		d := jitterUniform(interval, jitter)
		secs := d.Seconds()
		if secs < 1 || secs > 15 {
			t.Errorf("Uniform jitter out of range: %v (expected 5-15s)", d)
		}
	}
}

func TestJitterNormal_Range(t *testing.T) {
	interval := 60
	jitter := 30

	for i := 0; i < 200; i++ {
		d := jitterNormal(interval, jitter)
		secs := d.Seconds()
		minVal := float64(interval) - float64(interval)*float64(jitter)/100.0
		maxVal := float64(interval) + float64(interval)*float64(jitter)/100.0
		if secs < minVal-0.5 || secs > maxVal+0.5 {
			t.Errorf("Normal jitter out of range: %.1fs (expected %.0f-%.0f)", secs, minVal, maxVal)
		}
	}
}

func TestJitterNormal_ClustersCenterBias(t *testing.T) {
	interval := 100
	jitter := 50

	nearCenter := 0
	total := 1000
	for i := 0; i < total; i++ {
		d := jitterNormal(interval, jitter)
		secs := d.Seconds()
		if math.Abs(secs-float64(interval)) < float64(interval)*0.15 {
			nearCenter++
		}
	}
	centerRatio := float64(nearCenter) / float64(total)
	if centerRatio < 0.3 {
		t.Errorf("Normal distribution should cluster near center: only %.0f%% within 15%% of interval", centerRatio*100)
	}
}

func TestJitterExponential_Range(t *testing.T) {
	interval := 60
	jitter := 30

	for i := 0; i < 200; i++ {
		d := jitterExponential(interval, jitter)
		secs := d.Seconds()
		if secs < 1 {
			t.Errorf("Exponential jitter below minimum: %v", d)
		}
		maxVal := float64(interval) + float64(interval)*float64(jitter)/100.0
		if secs > maxVal+1 {
			t.Errorf("Exponential jitter too high: %.1fs (max expected %.0f)", secs, maxVal)
		}
	}
}

func TestJitterExponential_ShortBias(t *testing.T) {
	interval := 100
	jitter := 50

	belowInterval := 0
	total := 1000
	for i := 0; i < total; i++ {
		d := jitterExponential(interval, jitter)
		if d.Seconds() < float64(interval) {
			belowInterval++
		}
	}
	belowRatio := float64(belowInterval) / float64(total)
	if belowRatio < 0.2 {
		t.Errorf("Exponential should produce some below-interval values: only %.0f%%", belowRatio*100)
	}
}

func TestValidJitterProfile(t *testing.T) {
	valid := []string{"", "uniform", "normal", "exponential"}
	for _, p := range valid {
		if !ValidJitterProfile(p) {
			t.Errorf("Expected %q to be valid", p)
		}
	}

	invalid := []string{"gaussian", "random", "constant", "bell"}
	for _, p := range invalid {
		if ValidJitterProfile(p) {
			t.Errorf("Expected %q to be invalid", p)
		}
	}
}

func TestJitterProfileDescription(t *testing.T) {
	if JitterProfileDescription("normal") == "" {
		t.Error("Normal profile should have a description")
	}
	if JitterProfileDescription("exponential") == "" {
		t.Error("Exponential profile should have a description")
	}
	if JitterProfileDescription("") == "" {
		t.Error("Default profile should have a description")
	}
}

func TestCalculateAdaptiveSleep_ProfileRouting(t *testing.T) {
	profiles := []string{"uniform", "normal", "exponential"}
	for _, p := range profiles {
		d := CalculateAdaptiveSleep(10, 30, p)
		if d < 1*time.Second || d > 20*time.Second {
			t.Errorf("Profile %q: sleep %v out of reasonable range", p, d)
		}
	}
}
