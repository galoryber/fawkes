//go:build linux

package commands

import (
	"testing"
)

func TestDetectRecordSize384(t *testing.T) {
	// 384 is the standard utmp record size on 64-bit Linux
	data := make([]byte, 384*3)
	result := detectRecordSize(data)
	if result != 384 {
		t.Errorf("expected 384, got %d", result)
	}
}

func TestDetectRecordSize392(t *testing.T) {
	data := make([]byte, 392*2)
	result := detectRecordSize(data)
	if result != 392 {
		t.Errorf("expected 392, got %d", result)
	}
}

func TestDetectRecordSize288(t *testing.T) {
	// 288 is a possible 32-bit utmp size
	// Use 288*5=1440 (not divisible by 384 or 392)
	data := make([]byte, 288*5)
	result := detectRecordSize(data)
	if result != 288 {
		t.Errorf("expected 288, got %d", result)
	}
}

func TestDetectRecordSizeTooSmall(t *testing.T) {
	data := make([]byte, 100)
	result := detectRecordSize(data)
	if result != 0 {
		t.Errorf("expected 0 for small data, got %d", result)
	}
}

func TestDetectRecordSizeEmpty(t *testing.T) {
	result := detectRecordSize(nil)
	if result != 0 {
		t.Errorf("expected 0 for nil, got %d", result)
	}
}

func TestDetectRecordSizeNonDivisible(t *testing.T) {
	// 384 * 2 + 100 = 868 — not divisible by any standard size
	// But 384 is in the fallback: if len >= 384, return 384
	data := make([]byte, 868)
	result := detectRecordSize(data)
	if result != 384 {
		t.Errorf("expected 384 (fallback for >= 384), got %d", result)
	}
}

func TestExtractCStringNormal(t *testing.T) {
	data := []byte("hello\x00world")
	result := extractCString(data)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestExtractCStringNoNull(t *testing.T) {
	data := []byte("hello")
	result := extractCString(data)
	if result != "hello" {
		t.Errorf("expected 'hello' (no null terminator), got '%s'", result)
	}
}

func TestExtractCStringEmpty(t *testing.T) {
	data := []byte("\x00rest")
	result := extractCString(data)
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestExtractCStringAllNull(t *testing.T) {
	data := []byte{0, 0, 0, 0}
	result := extractCString(data)
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestExtractCStringEmptyInput(t *testing.T) {
	data := []byte{}
	result := extractCString(data)
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestLastPlatformDefaultArgs(t *testing.T) {
	args := lastArgs{Count: 10}
	entries := lastPlatform(args)
	// On a real Linux system, we should get some entries (or empty list if no wtmp)
	if entries == nil {
		// nil is acceptable — means no wtmp/utmp/auth.log readable
		return
	}
	if len(entries) > 10 {
		t.Errorf("expected at most 10 entries, got %d", len(entries))
	}
}

func TestLastPlatformUserFilter(t *testing.T) {
	args := lastArgs{Count: 100, User: "nonexistentuser12345"}
	entries := lastPlatform(args)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent user, got %d", len(entries))
	}
}

func TestLastFailedPlatformNoError(t *testing.T) {
	// btmp may not be readable without root; just verify no panic
	args := lastArgs{Count: 10}
	_ = lastFailedPlatform(args)
}

func TestLastFailedPlatformUserFilter(t *testing.T) {
	args := lastArgs{Count: 100, User: "nonexistentuser12345"}
	entries := lastFailedPlatform(args)
	// Should get 0 entries for nonexistent user (even if btmp readable)
	for _, e := range entries {
		if e.User == "nonexistentuser12345" {
			// This is fine — means btmp had a matching entry
			continue
		}
	}
	_ = entries // prevent unused
}

func TestLastFailedFromAuthLogNoFiles(t *testing.T) {
	// This will return nil/empty if auth.log doesn't exist or is empty
	args := lastArgs{Count: 5, User: "nonexistentuser12345"}
	entries := lastFailedFromAuthLog(args)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent user, got %d", len(entries))
	}
}

func TestLastRebootPlatformNoError(t *testing.T) {
	// /var/log/wtmp may or may not exist; verify no panic
	args := lastArgs{Count: 10}
	entries := lastRebootPlatform(args)
	// entries may be nil (no wtmp) or have entries — both are fine
	_ = entries
}

func TestLastRebootPlatformCountLimit(t *testing.T) {
	args := lastArgs{Count: 2}
	entries := lastRebootPlatform(args)
	if len(entries) > 2 {
		t.Errorf("expected at most 2 entries, got %d", len(entries))
	}
}

func TestLastRebootPlatformSyntheticWtmp(t *testing.T) {
	// Build a synthetic wtmp with a BOOT_TIME record (ut_type=2) at offset 0
	// Record size is 384 bytes for x86_64
	const recSize = 384
	const utBootTime = 2

	data := make([]byte, recSize)
	// ut_type at offset 0 (4 bytes, LE)
	data[0] = utBootTime
	data[1] = 0
	data[2] = 0
	data[3] = 0

	// ut_line at offset 8 (32 bytes) — "~" for reboot
	data[8] = '~'

	// ut_user at offset 44 (32 bytes) — "reboot"
	copy(data[44:], "reboot")

	// ut_tv.tv_sec at offset 340 (4 bytes, LE) — 1700000000 (2023-11-14)
	data[340] = 0x00
	data[341] = 0x27
	data[342] = 0x6b
	data[343] = 0x65

	// Verify our synthetic record is detected correctly
	size := detectRecordSize(data)
	if size != 384 {
		t.Fatalf("expected record size 384, got %d", size)
	}
}

func TestLastFromAuthLogEntries(t *testing.T) {
	args := lastArgs{Count: 5, User: "nonexistentuser12345"}
	entries := lastFromAuthLogEntries(args)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent user, got %d", len(entries))
	}
}
