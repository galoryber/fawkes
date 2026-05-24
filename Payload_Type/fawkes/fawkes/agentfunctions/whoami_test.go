package agentfunctions

import "testing"

func TestParseIntegrityLevel(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want int
	}{
		{"system", "System", 4},
		{"system lower", "system", 4},
		{"system with extra", "System Mandatory Level", 4},
		{"high", "High", 3},
		{"high lower", "high", 3},
		{"medium", "Medium", 2},
		{"medium lower", "medium", 2},
		{"medium mandatory", "Medium Mandatory Level", 2},
		{"low", "Low", 1},
		{"untrusted", "Untrusted", 0},
		{"unknown", "something", -1},
		{"empty", "", -1},
		{"numeric", "4", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIntegrityLevel(tt.val)
			if got != tt.want {
				t.Errorf("parseIntegrityLevel(%q) = %d, want %d", tt.val, got, tt.want)
			}
		})
	}
}
