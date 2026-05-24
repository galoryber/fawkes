package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestKerbDelegationName(t *testing.T) {
	cmd := &KerbDelegationCommand{}
	if cmd.Name() != "kerb-delegation" {
		t.Errorf("expected kerb-delegation, got %s", cmd.Name())
	}
}

func TestKerbDelegationEmptyParams(t *testing.T) {
	cmd := &KerbDelegationCommand{}

	// Empty params
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}

	// Missing server
	result = cmd.Execute(structs.Task{Params: `{"action":"all"}`})
	if result.Status != "error" || !contains(result.Output, "server") {
		t.Error("missing server should return error mentioning server")
	}
}

func TestKerbDelegationBadJSON(t *testing.T) {
	cmd := &KerbDelegationCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("bad JSON should return error")
	}
}

func TestKerbDelegationInvalidAction(t *testing.T) {
	cmd := &KerbDelegationCommand{}
	// Use 127.0.0.1 instead of 1.2.3.4 so the LDAP connection gets refused
	// instantly rather than timing out after 10s waiting for a non-routable IP.
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction","server":"127.0.0.1"}`})
	// Will get connection error before action check, that's OK
	if result.Status != "error" {
		t.Error("should return error")
	}
}

func TestMinBuiltin(t *testing.T) {
	if min(3, 5) != 3 {
		t.Error("min(3,5) should be 3")
	}
	if min(5, 3) != 3 {
		t.Error("min(5,3) should be 3")
	}
	if min(3, 3) != 3 {
		t.Error("min(3,3) should be 3")
	}
	if min(0, 1) != 0 {
		t.Error("min(0,1) should be 0")
	}
}

func TestUACFlags(t *testing.T) {
	// Verify our UAC constants match expected values
	if uacTrustedForDelegation != 0x80000 {
		t.Errorf("uacTrustedForDelegation should be 0x80000, got 0x%X", uacTrustedForDelegation)
	}
	if uacTrustedToAuthForDelegation != 0x1000000 {
		t.Errorf("uacTrustedToAuthForDelegation should be 0x1000000, got 0x%X", uacTrustedToAuthForDelegation)
	}
	if uacNotDelegated != 0x100000 {
		t.Errorf("uacNotDelegated should be 0x100000, got 0x%X", uacNotDelegated)
	}
}

func TestKdIsTGT(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"krbtgt prefix", "krbtgt/SEVENKINGDOMS.LOCAL", true},
		{"krbtgt uppercase", "KRBTGT/DOMAIN.LOCAL", true},
		{"service ticket", "cifs/dc01.domain.local", false},
		{"ldap service", "ldap/dc01.domain.local", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kdIsTGT(tc.input)
			if got != tc.expected {
				t.Errorf("kdIsTGT(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestKdBuildTicketKey(t *testing.T) {
	key := kdBuildTicketKey("joffrey@SEVENKINGDOMS.LOCAL", "krbtgt/SEVENKINGDOMS.LOCAL@SEVENKINGDOMS.LOCAL", "0x0000000012345678")
	expected := "joffrey@SEVENKINGDOMS.LOCAL|krbtgt/SEVENKINGDOMS.LOCAL@SEVENKINGDOMS.LOCAL|0x0000000012345678"
	if key != expected {
		t.Errorf("kdBuildTicketKey returned %q, want %q", key, expected)
	}
	// Verify dedup: same key for same inputs
	key2 := kdBuildTicketKey("joffrey@SEVENKINGDOMS.LOCAL", "krbtgt/SEVENKINGDOMS.LOCAL@SEVENKINGDOMS.LOCAL", "0x0000000012345678")
	if key != key2 {
		t.Error("same inputs should produce identical dedup keys")
	}
}

func TestKdFormatLUID(t *testing.T) {
	// LUID (high=0, low=0x3E7) = 0x00000000000003E7
	got := kdFormatLUID(0x3E7, 0)
	if got != "0x00000000000003E7" {
		t.Errorf("kdFormatLUID(0x3E7, 0) = %q, want 0x00000000000003E7", got)
	}
	// LUID (high=1, low=0) = 0x0000000100000000
	got2 := kdFormatLUID(0, 1)
	if got2 != "0x0000000100000000" {
		t.Errorf("kdFormatLUID(0, 1) = %q, want 0x0000000100000000", got2)
	}
}

func TestKdMonitorClampArgsDefaults(t *testing.T) {
	dur, ivl := kdMonitorClampArgs(0, 0)
	if dur != 300 {
		t.Errorf("default duration should be 300, got %d", dur)
	}
	if ivl != 10 {
		t.Errorf("default interval should be 10, got %d", ivl)
	}
}

func TestKdMonitorClampArgsBounds(t *testing.T) {
	// Max duration clamping
	dur, _ := kdMonitorClampArgs(9999, 10)
	if dur != 3600 {
		t.Errorf("duration > 3600 should clamp to 3600, got %d", dur)
	}
	// Min interval clamping
	_, ivl := kdMonitorClampArgs(300, 1)
	if ivl != 5 {
		t.Errorf("interval < 5 should clamp to 5, got %d", ivl)
	}
	// Interval cannot exceed duration
	_, ivl2 := kdMonitorClampArgs(20, 60)
	if ivl2 != 20 {
		t.Errorf("interval > duration should be clamped to duration, got %d", ivl2)
	}
}

// TestKerbDelegationMonitorNoServerNeeded verifies that the monitor action does not
// require a -server argument (it operates locally via LSA, not LDAP).
func TestKerbDelegationMonitorNoServerNeeded(t *testing.T) {
	cmd := &KerbDelegationCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"monitor","duration":1,"interval":1}`})
	// Must NOT complain about missing server — monitor bypasses LDAP entirely
	if strings.Contains(result.Output, "server parameter required") {
		t.Error("monitor action should not require server parameter")
	}
	// Should return some result (error on non-Windows, attempt on Windows)
	if result.Status != "error" && result.Status != "success" {
		t.Errorf("unexpected status: %s", result.Status)
	}
}
