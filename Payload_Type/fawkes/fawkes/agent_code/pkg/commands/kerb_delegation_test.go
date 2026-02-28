package commands

import (
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

func TestMinInt(t *testing.T) {
	if minInt(3, 5) != 3 {
		t.Error("minInt(3,5) should be 3")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) should be 3")
	}
	if minInt(3, 3) != 3 {
		t.Error("minInt(3,3) should be 3")
	}
	if minInt(0, 1) != 0 {
		t.Error("minInt(0,1) should be 0")
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
