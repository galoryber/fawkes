//go:build linux

package commands

import (
	"testing"
)

func TestGetArpTable(t *testing.T) {
	// Read the actual ARP table — should work in CI (ubuntu-latest)
	entries, err := getArpTable()
	if err != nil {
		t.Fatalf("getArpTable() failed: %v", err)
	}
	// It's valid for ARP table to be empty in CI, but shouldn't error
	for i, e := range entries {
		if e.IP == "" {
			t.Errorf("entry[%d] has empty IP", i)
		}
		if e.MAC == "" {
			t.Errorf("entry[%d] has empty MAC", i)
		}
		if e.MAC == "00:00:00:00:00:00" {
			t.Errorf("entry[%d] should not have zero MAC (filtered out)", i)
		}
		if e.Interface == "" {
			t.Errorf("entry[%d] has empty interface", i)
		}
		validTypes := map[string]bool{"dynamic": true, "static": true, "incomplete": true}
		if !validTypes[e.Type] {
			t.Errorf("entry[%d] has unexpected type %q", i, e.Type)
		}
	}
}

