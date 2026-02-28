package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

func TestArpCommandName(t *testing.T) {
	cmd := &ArpCommand{}
	if cmd.Name() != "arp" {
		t.Errorf("expected 'arp', got %q", cmd.Name())
	}
}

func TestArpCommandDescription(t *testing.T) {
	cmd := &ArpCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestArpIsMACAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"00:11:22:33:44:55", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"00-11-22-33-44-55", true},
		{"not a mac", false},
		{"192.168.1.1", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isMACAddress(tc.input)
		if got != tc.expected {
			t.Errorf("isMACAddress(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestArpContainsMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1 00:11:22:33:44:55 eth0", true},
		{"just some text", false},
		{"00:11:22:33:44:55", true},
	}
	for _, tc := range tests {
		got := containsMAC(tc.input)
		if got != tc.expected {
			t.Errorf("containsMAC(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestArpExecute(t *testing.T) {
	cmd := &ArpCommand{}
	task := structs.NewTask("t", "arp", "")
	result := cmd.Execute(task)
	// ARP table read should succeed or report empty
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
	if !result.Completed {
		t.Error("should be completed")
	}
}
