//go:build !windows

package commands

import (
	"testing"
)

func TestFormatDarwinHash(t *testing.T) {
	tests := []struct {
		name     string
		entry    darwinHashEntry
		expected string
	}{
		{
			name: "SALTED-SHA512-PBKDF2",
			entry: darwinHashEntry{
				HashType:   "SALTED-SHA512-PBKDF2",
				Iterations: 45000,
				Salt:       "aabb00",
				Entropy:    "ccdd11",
			},
			expected: "$ml$45000$aabb00$ccdd11",
		},
		{
			name: "SALTED-SHA512 (Lion)",
			entry: darwinHashEntry{
				HashType: "SALTED-SHA512",
				Salt:     "aabb",
				Entropy:  "ccddee",
			},
			expected: "$LION$aabbccddee",
		},
		{
			name: "SRP format",
			entry: darwinHashEntry{
				HashType:   "SRP-RFC5054-4096-SHA512-PBKDF2",
				Iterations: 4096,
				Salt:       "salt",
				Entropy:    "entropy",
			},
			expected: "$SRP-RFC5054-4096-SHA512-PBKDF2$4096$salt$entropy",
		},
		{
			name: "unknown no data",
			entry: darwinHashEntry{
				HashType: "unknown (SecureToken)",
			},
			expected: "unknown (SecureToken)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDarwinHash(tt.entry)
			if got != tt.expected {
				t.Errorf("formatDarwinHash() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFormatDarwinHash_ZeroIterations(t *testing.T) {
	entry := darwinHashEntry{
		HashType:   "SALTED-SHA512-PBKDF2",
		Iterations: 0,
		Salt:       "abc",
		Entropy:    "def",
	}
	got := formatDarwinHash(entry)
	if got != "$ml$0$abc$def" {
		t.Errorf("got %q, want $ml$0$abc$def", got)
	}
}
