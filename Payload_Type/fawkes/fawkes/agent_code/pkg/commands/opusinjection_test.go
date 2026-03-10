//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestStringsEqualFold_Basic(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"hello", "hello", true},
		{"Hello", "hello", true},
		{"HELLO", "hello", true},
		{"HeLLo", "hEllO", true},
		{"abc", "ABC", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "", true},
		{"a", "", false},
		{"", "a", false},
	}

	for _, tt := range tests {
		result := stringsEqualFold(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("stringsEqualFold(%q, %q): expected %v, got %v", tt.a, tt.b, tt.expected, result)
		}
	}
}

func TestStringsEqualFold_DLLNames(t *testing.T) {
	// Typical use case: comparing DLL/module names
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"kernel32.dll", "KERNEL32.DLL", true},
		{"ntdll.dll", "Ntdll.Dll", true},
		{"user32.dll", "USER32.DLL", true},
		{"kernelbase.dll", "kernel32.dll", false},
	}

	for _, tt := range tests {
		result := stringsEqualFold(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("stringsEqualFold(%q, %q): expected %v, got %v", tt.a, tt.b, tt.expected, result)
		}
	}
}

func TestStringsEqualFold_NonAlpha(t *testing.T) {
	// Non-alphabetic characters should be compared exactly
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"file.txt", "FILE.TXT", true},
		{"path\\to\\file", "PATH\\TO\\FILE", true},
		{"123", "123", true},
		{"abc123", "ABC123", true},
		{"a-b_c", "A-B_C", true},
	}

	for _, tt := range tests {
		result := stringsEqualFold(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("stringsEqualFold(%q, %q): expected %v, got %v", tt.a, tt.b, tt.expected, result)
		}
	}
}

func TestEncodePointer_ZeroCookie(t *testing.T) {
	// With cookie=0, XOR is identity and rotate by 0 is identity
	ptr := uintptr(0x12345678)
	result := encodePointer(ptr, 0)
	if result != ptr {
		t.Errorf("cookie=0: expected 0x%X, got 0x%X", ptr, result)
	}
}

func TestEncodePointer_XOROnly(t *testing.T) {
	// Cookie with rotateAmount = cookie & 0x3F = 0 means only XOR applies
	// cookie = 0x40 → 0x40 & 0x3F = 0 → no rotation
	ptr := uintptr(0xFF00FF00)
	cookie := uint32(0x40)
	result := encodePointer(ptr, cookie)
	expected := ptr ^ uintptr(cookie)
	if result != expected {
		t.Errorf("XOR-only: expected 0x%X, got 0x%X", expected, result)
	}
}

func TestEncodePointer_Deterministic(t *testing.T) {
	ptr := uintptr(0xDEADBEEFCAFEBABE)
	cookie := uint32(0x12345678)

	r1 := encodePointer(ptr, cookie)
	r2 := encodePointer(ptr, cookie)

	if r1 != r2 {
		t.Errorf("same inputs should produce same output: 0x%X vs 0x%X", r1, r2)
	}
}

func TestEncodePointer_DifferentCookies(t *testing.T) {
	ptr := uintptr(0x0000000100000001)

	r1 := encodePointer(ptr, 0x11111111)
	r2 := encodePointer(ptr, 0x22222222)

	if r1 == r2 {
		t.Error("different cookies should produce different encoded values")
	}
}

func TestEncodePointer_RotateAmount(t *testing.T) {
	// With cookie = 1, rotate right by 1 bit
	// ptr XOR 1, then ROR by 1
	ptr := uintptr(0x02)
	cookie := uint32(1)
	xored := ptr ^ uintptr(cookie) // 0x02 ^ 0x01 = 0x03
	// ROR(0x03, 1) on 64-bit: 0x8000000000000001
	result := encodePointer(ptr, cookie)
	expected := (xored >> 1) | (xored << 63)
	if result != expected {
		t.Errorf("rotate by 1: expected 0x%X, got 0x%X", expected, result)
	}
}
