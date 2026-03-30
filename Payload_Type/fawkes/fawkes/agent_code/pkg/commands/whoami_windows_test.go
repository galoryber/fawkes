//go:build windows

package commands

import "testing"

func TestWhoamiCommandName(t *testing.T) {
	cmd := &WhoamiCommand{}
	if cmd.Name() != "whoami" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "whoami")
	}
}

func TestWhoamiCommandDescription(t *testing.T) {
	cmd := &WhoamiCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestIntegrityLevelName(t *testing.T) {
	tests := []struct {
		rid  uint32
		want string
	}{
		{0x0000, "Untrusted"},
		{0x1000, "Low"},
		{0x2000, "Medium"},
		{0x3000, "High"},
		{0x4000, "System"},
	}
	for _, tt := range tests {
		got := integrityLevelName(tt.rid)
		if got != tt.want {
			t.Errorf("integrityLevelName(0x%04X) = %q, want %q", tt.rid, got, tt.want)
		}
	}
}
