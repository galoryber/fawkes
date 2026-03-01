//go:build linux

package commands

import (
	"testing"
)

func TestHexToIP_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"00000000", "0.0.0.0"},
		{"0100000A", "10.0.0.1"},        // 10.0.0.1 in little-endian hex
		{"0100A8C0", "192.168.0.1"},     // 192.168.0.1
		{"FFFFFFFF", "255.255.255.255"}, // broadcast
		{"0100007F", "127.0.0.1"},       // loopback
		{"0064A8C0", "192.168.100.0"},   // 192.168.100.0
	}
	for _, tc := range tests {
		got := hexToIP(tc.input)
		if got != tc.want {
			t.Errorf("hexToIP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestHexToIP_Invalid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},                     // empty
		{"00", "00"},                 // too short
		{"ZZZZZZZZ", "ZZZZZZZZ"},     // invalid hex
		{"00000000FF", "00000000FF"}, // too long
	}
	for _, tc := range tests {
		got := hexToIP(tc.input)
		if got != tc.want {
			t.Errorf("hexToIP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestLinuxRouteFlags(t *testing.T) {
	tests := []struct {
		flags uint32
		want  string
	}{
		{0x0001, "U"},           // Up
		{0x0002, "G"},           // Gateway
		{0x0003, "UG"},          // Up + Gateway (default route)
		{0x0005, "UH"},          // Up + Host
		{0x0001 | 0x0010, "UD"}, // Up + Dynamic
		{0x0001 | 0x0020, "UM"}, // Up + Modified
		{0x0000, "-"},           // No flags
		{0x003F, "UGHRDM"},      // All flags
	}
	for _, tc := range tests {
		got := linuxRouteFlags(tc.flags)
		if got != tc.want {
			t.Errorf("linuxRouteFlags(0x%04x) = %q, want %q", tc.flags, got, tc.want)
		}
	}
}

func TestHexToIPv6_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"00000000000000000000000000000000", "::"},
		{"00000000000000000000000000000001", "::1"},
		{"fe800000000000000000000000000001", "fe80::1"},
		{"20010db8000000000000000000000001", "2001:db8::1"},
	}
	for _, tc := range tests {
		got := hexToIPv6(tc.input)
		if got != tc.want {
			t.Errorf("hexToIPv6(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestHexToIPv6_Invalid(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},                                 // empty
		{"0000"},                             // too short
		{"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}, // invalid hex
	}
	for _, tc := range tests {
		got := hexToIPv6(tc.input)
		if got != tc.input {
			t.Errorf("hexToIPv6(%q) = %q, want passthrough", tc.input, got)
		}
	}
}

func TestDestPrefixToLen(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"40", "64"},  // /64 prefix
		{"80", "128"}, // /128 prefix
		{"00", "0"},   // /0 default
		{"30", "48"},  // /48
		{"10", "16"},  // /16
	}
	for _, tc := range tests {
		got := destPrefixToLen(tc.input)
		if got != tc.want {
			t.Errorf("destPrefixToLen(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestDestPrefixToLen_Invalid(t *testing.T) {
	got := destPrefixToLen("ZZ")
	if got != "ZZ" {
		t.Errorf("destPrefixToLen(\"ZZ\") = %q, want passthrough", got)
	}
}

func TestEnumerateRoutes(t *testing.T) {
	// This test reads actual /proc/net/route — should work in CI (ubuntu-latest)
	routes, err := enumerateRoutes()
	if err != nil {
		t.Fatalf("enumerateRoutes() failed: %v", err)
	}
	// Every Linux system should have at least one route
	if len(routes) == 0 {
		t.Error("expected at least one route")
	}
	// Check that routes have required fields
	for i, r := range routes {
		if r.Interface == "" {
			t.Errorf("route[%d] has empty interface", i)
		}
		if r.Destination == "" {
			t.Errorf("route[%d] has empty destination", i)
		}
	}
}
