//go:build windows

package commands

import (
	"strings"
	"testing"
)

func TestKnownEDRDriversDatabase(t *testing.T) {
	if len(knownEDRDrivers) < 30 {
		t.Errorf("knownEDRDrivers has %d entries, want at least 30", len(knownEDRDrivers))
	}

	for name, info := range knownEDRDrivers {
		if name != strings.ToLower(name) {
			t.Errorf("driver key %q is not lowercase", name)
		}
		if info.vendor == "" {
			t.Errorf("driver %q has empty vendor", name)
		}
		if info.product == "" {
			t.Errorf("driver %q has empty product", name)
		}
		if info.callbacks == "" {
			t.Errorf("driver %q has empty callbacks", name)
		}
	}
}

func TestKnownEDRDriversCallbackTypes(t *testing.T) {
	validTypes := map[string]bool{
		"minifilter": true, "process": true, "thread": true,
		"image": true, "registry": true, "object": true,
		"network": true, "boot": true, "framework": true,
		"crypto": true,
	}

	for name, info := range knownEDRDrivers {
		parts := strings.Split(info.callbacks, ",")
		for _, p := range parts {
			if !validTypes[p] {
				t.Errorf("driver %q has unknown callback type %q", name, p)
			}
		}
	}
}

func TestBytesToGoString(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{[]byte("hello\x00world"), "hello"},
		{[]byte("\x00"), ""},
		{[]byte("noterm"), "noterm"},
		{[]byte("\\SystemRoot\\system32\\ntoskrnl.exe\x00"), "\\SystemRoot\\system32\\ntoskrnl.exe"},
	}

	for _, tt := range tests {
		got := bytesToGoString(tt.input)
		if got != tt.want {
			t.Errorf("bytesToGoString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
