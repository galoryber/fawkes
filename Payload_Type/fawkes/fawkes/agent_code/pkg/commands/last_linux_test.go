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
