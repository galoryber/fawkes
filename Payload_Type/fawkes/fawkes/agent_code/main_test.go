package main

import (
	"testing"
	"time"
)

// --- calculateSleepTime Tests ---

func TestCalculateSleepTime_ZeroJitter(t *testing.T) {
	duration := calculateSleepTime(10, 0)
	expected := 10 * time.Second
	if duration != expected {
		t.Errorf("calculateSleepTime(10, 0) = %v, want %v", duration, expected)
	}
}

func TestCalculateSleepTime_ZeroInterval(t *testing.T) {
	duration := calculateSleepTime(0, 0)
	if duration != 0 {
		t.Errorf("calculateSleepTime(0, 0) = %v, want 0", duration)
	}
}

func TestCalculateSleepTime_WithJitter_InRange(t *testing.T) {
	interval := 10
	jitter := 50

	// Run multiple times to test the randomness boundaries
	for i := 0; i < 100; i++ {
		duration := calculateSleepTime(interval, jitter)
		seconds := int(duration / time.Second)

		// With 50% jitter on 10s interval:
		// Max jitter diff = 10 * 50/100 = 5
		// Range: [10-5, 10+5] = [5, 15], but clamped to min 1
		if seconds < 1 || seconds > 15 {
			t.Errorf("iteration %d: calculateSleepTime(%d, %d) = %v (%ds), want between 1s and 15s",
				i, interval, jitter, duration, seconds)
		}
	}
}

func TestCalculateSleepTime_FullJitter(t *testing.T) {
	interval := 10
	jitter := 100

	for i := 0; i < 100; i++ {
		duration := calculateSleepTime(interval, jitter)
		seconds := int(duration / time.Second)

		// With 100% jitter on 10s interval:
		// Max jitter diff = 10 * (0-99)/100
		// Range: [1, 20] (clamped to min 1)
		if seconds < 1 || seconds > 20 {
			t.Errorf("iteration %d: calculateSleepTime(%d, %d) = %v (%ds), out of expected range",
				i, interval, jitter, duration, seconds)
		}
	}
}

func TestCalculateSleepTime_MinClamp(t *testing.T) {
	// Small interval with high jitter should never go below 1 second
	interval := 1
	jitter := 100

	for i := 0; i < 100; i++ {
		duration := calculateSleepTime(interval, jitter)
		if duration < 1*time.Second {
			t.Errorf("iteration %d: calculateSleepTime(%d, %d) = %v, should not be less than 1s",
				i, interval, jitter, duration)
		}
	}
}

func TestCalculateSleepTime_LargeInterval(t *testing.T) {
	duration := calculateSleepTime(3600, 0) // 1 hour, no jitter
	expected := 3600 * time.Second
	if duration != expected {
		t.Errorf("calculateSleepTime(3600, 0) = %v, want %v", duration, expected)
	}
}

func TestCalculateSleepTime_OneSecond(t *testing.T) {
	duration := calculateSleepTime(1, 0)
	expected := 1 * time.Second
	if duration != expected {
		t.Errorf("calculateSleepTime(1, 0) = %v, want %v", duration, expected)
	}
}

// --- getHostname Tests ---

func TestGetHostname_NotEmpty(t *testing.T) {
	hostname := getHostname()
	if hostname == "" {
		t.Error("getHostname() returned empty string")
	}
}

func TestGetHostname_NotUnknown(t *testing.T) {
	// On a normal system, hostname should be available
	hostname := getHostname()
	if hostname == "unknown" {
		t.Log("getHostname() returned 'unknown' — may be expected in some environments")
	}
}

// --- getUsername Tests ---

func TestGetUsername_NotEmpty(t *testing.T) {
	username := getUsername()
	if username == "" {
		t.Error("getUsername() returned empty string")
	}
}

func TestGetUsername_NotUnknown(t *testing.T) {
	username := getUsername()
	if username == "unknown" {
		t.Log("getUsername() returned 'unknown' — may be expected in some environments")
	}
}

// --- getOperatingSystem Tests ---

func TestGetOperatingSystem_Linux(t *testing.T) {
	os := getOperatingSystem()
	if os != "linux" {
		t.Errorf("getOperatingSystem() = %q, want 'linux' (running on Linux)", os)
	}
}

// --- getInternalIP Tests ---

func TestGetInternalIP_NotEmpty(t *testing.T) {
	ip := getInternalIP()
	if ip == "" {
		t.Error("getInternalIP() returned empty string")
	}
}

func TestGetInternalIP_ValidFormat(t *testing.T) {
	ip := getInternalIP()
	// Should be either a valid IPv4 or "127.0.0.1" fallback
	parts := 0
	for _, c := range ip {
		if c == '.' {
			parts++
		}
	}
	if parts != 3 {
		t.Errorf("getInternalIP() = %q, doesn't look like a valid IPv4 address", ip)
	}
}

func TestGetInternalIP_NotLoopback(t *testing.T) {
	ip := getInternalIP()
	// On a system with network interfaces, should return a non-loopback address
	// (127.0.0.1 is the fallback when no interfaces are found)
	if ip == "127.0.0.1" {
		t.Log("getInternalIP() returned loopback — system may not have non-loopback interfaces")
	}
}

// --- getIntegrityLevel Tests ---

func TestGetIntegrityLevel_ValidRange(t *testing.T) {
	level := getIntegrityLevel()
	// Valid integrity levels: 1 (low), 2 (medium), 3 (high/admin), 4 (system/root)
	if level < 1 || level > 4 {
		t.Errorf("getIntegrityLevel() = %d, want 1-4", level)
	}
}

func TestGetIntegrityLevel_NonRootIsMedium(t *testing.T) {
	level := getIntegrityLevel()
	// Running tests as non-root should return 2 (medium)
	// Running as root should return 4 (system)
	if level != 2 && level != 4 {
		t.Errorf("getIntegrityLevel() = %d, want 2 (non-root) or 4 (root)", level)
	}
}
