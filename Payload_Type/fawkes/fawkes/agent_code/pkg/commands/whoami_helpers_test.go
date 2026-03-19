package commands

import (
	"testing"
)

func TestParseLinuxCapabilitiesNone(t *testing.T) {
	caps := parseLinuxCapabilities("0000000000000000")
	if len(caps) != 0 {
		t.Errorf("expected 0 caps for zero value, got %d: %v", len(caps), caps)
	}
}

func TestParseLinuxCapabilitiesSingle(t *testing.T) {
	// Bit 0 = CAP_CHOWN
	caps := parseLinuxCapabilities("0000000000000001")
	if len(caps) != 1 {
		t.Fatalf("expected 1 cap, got %d: %v", len(caps), caps)
	}
	if caps[0] != "CAP_CHOWN" {
		t.Errorf("expected CAP_CHOWN, got %s", caps[0])
	}
}

func TestParseLinuxCapabilitiesNetRaw(t *testing.T) {
	// Bit 13 = CAP_NET_RAW = 0x2000
	caps := parseLinuxCapabilities("0000000000002000")
	if len(caps) != 1 {
		t.Fatalf("expected 1 cap, got %d: %v", len(caps), caps)
	}
	if caps[0] != "CAP_NET_RAW" {
		t.Errorf("expected CAP_NET_RAW, got %s", caps[0])
	}
}

func TestParseLinuxCapabilitiesMultiple(t *testing.T) {
	// CAP_CHOWN (0) + CAP_SETUID (7) + CAP_NET_RAW (13)
	// = 0x1 | 0x80 | 0x2000 = 0x2081
	caps := parseLinuxCapabilities("0000000000002081")
	if len(caps) != 3 {
		t.Fatalf("expected 3 caps, got %d: %v", len(caps), caps)
	}
	expected := []string{"CAP_CHOWN", "CAP_SETUID", "CAP_NET_RAW"}
	for i, want := range expected {
		if caps[i] != want {
			t.Errorf("caps[%d] = %s, want %s", i, caps[i], want)
		}
	}
}

func TestParseLinuxCapabilitiesFull(t *testing.T) {
	// All 41 capabilities set: (1 << 41) - 1 = 0x1ffffffffff
	caps := parseLinuxCapabilities("000001ffffffffff")
	if len(caps) != len(linuxCapNames) {
		t.Errorf("expected %d caps for full set, got %d", len(linuxCapNames), len(caps))
	}
	// First and last should be correct
	if caps[0] != "CAP_CHOWN" {
		t.Errorf("first cap = %s, want CAP_CHOWN", caps[0])
	}
	if caps[len(caps)-1] != "CAP_CHECKPOINT_RESTORE" {
		t.Errorf("last cap = %s, want CAP_CHECKPOINT_RESTORE", caps[len(caps)-1])
	}
}

func TestParseLinuxCapabilitiesUnknownBits(t *testing.T) {
	// Set bit 63 (beyond known caps)
	caps := parseLinuxCapabilities("8000000000000000")
	if len(caps) != 1 {
		t.Fatalf("expected 1 entry (unknown), got %d: %v", len(caps), caps)
	}
	if caps[0] != "UNKNOWN(0x8000000000000000)" {
		t.Errorf("expected UNKNOWN marker, got %s", caps[0])
	}
}

func TestParseLinuxCapabilitiesInvalidHex(t *testing.T) {
	caps := parseLinuxCapabilities("not-a-hex-value")
	if caps != nil {
		t.Errorf("expected nil for invalid hex, got %v", caps)
	}
}

func TestParseLinuxCapabilitiesEmpty(t *testing.T) {
	caps := parseLinuxCapabilities("")
	if caps != nil {
		t.Errorf("expected nil for empty string, got %v", caps)
	}
}

func TestParseLinuxCapabilitiesWithWhitespace(t *testing.T) {
	// /proc/self/status lines often have leading/trailing whitespace
	caps := parseLinuxCapabilities("  0000000000002000  ")
	if len(caps) != 1 || caps[0] != "CAP_NET_RAW" {
		t.Errorf("expected [CAP_NET_RAW], got %v", caps)
	}
}

func TestIsFullCapabilitiesTrue(t *testing.T) {
	if !isFullCapabilities("000001ffffffffff") {
		t.Error("expected true for all capabilities set")
	}
}

func TestIsFullCapabilitiesFalse(t *testing.T) {
	if isFullCapabilities("0000000000000001") {
		t.Error("expected false for single capability")
	}
}

func TestIsFullCapabilitiesZero(t *testing.T) {
	if isFullCapabilities("0000000000000000") {
		t.Error("expected false for zero capabilities")
	}
}

func TestIsFullCapabilitiesInvalid(t *testing.T) {
	if isFullCapabilities("invalid") {
		t.Error("expected false for invalid hex")
	}
}

func TestIsFullCapabilitiesSuperset(t *testing.T) {
	// Extra bits beyond known caps should still return true
	if !isFullCapabilities("ffffffffffffffff") {
		t.Error("expected true when all known bits plus extra bits are set")
	}
}
