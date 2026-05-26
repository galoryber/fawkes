package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestParseLDAPRelayOps_Defaults(t *testing.T) {
	params := sniffParams{
		ResponseIP: "dc01.corp.local",
	}
	ops := parseLDAPRelayOps(params)

	if ops.target != "dc01.corp.local" {
		t.Errorf("target = %q, want dc01.corp.local", ops.target)
	}
	if ops.targetPort != 389 {
		t.Errorf("targetPort = %d, want 389", ops.targetPort)
	}
	if ops.listenPort != 80 {
		t.Errorf("listenPort = %d, want 80", ops.listenPort)
	}
	if ops.operation != "whoami" {
		t.Errorf("operation = %q, want whoami", ops.operation)
	}
	if ops.duration != 120 {
		t.Errorf("duration = %d, want 120", ops.duration)
	}
}

func TestParseLDAPRelayOps_CustomPorts(t *testing.T) {
	params := sniffParams{
		ResponseIP: "dc01",
		Ports:      "8080:636",
	}
	ops := parseLDAPRelayOps(params)
	if ops.listenPort != 8080 {
		t.Errorf("listenPort = %d, want 8080", ops.listenPort)
	}
	if ops.targetPort != 636 {
		t.Errorf("targetPort = %d, want 636", ops.targetPort)
	}
}

func TestParseLDAPRelayOps_SinglePort(t *testing.T) {
	params := sniffParams{
		ResponseIP: "dc01",
		Ports:      "636",
	}
	ops := parseLDAPRelayOps(params)
	if ops.targetPort != 636 {
		t.Errorf("targetPort = %d, want 636", ops.targetPort)
	}
}

func TestParseLDAPRelayOps_Operations(t *testing.T) {
	tests := []struct {
		protocols string
		wantOp    string
		wantTgt   string
		wantVal   string
	}{
		{"whoami", "whoami", "", ""},
		{"add-computer:FAWKES$", "add-computer", "FAWKES$", ""},
		{"rbcd:CN=DC01,DC=corp,DC=local|S-1-5-21-123", "rbcd", "CN=DC01,DC=corp,DC=local", "S-1-5-21-123"},
		{"dump-laps", "dump-laps", "", ""},
		{"dump-laps:SRV01", "dump-laps", "SRV01", ""},
	}

	for _, tt := range tests {
		params := sniffParams{
			ResponseIP: "dc01",
			Protocols:  tt.protocols,
		}
		ops := parseLDAPRelayOps(params)
		if ops.operation != tt.wantOp {
			t.Errorf("protocols=%q: operation = %q, want %q", tt.protocols, ops.operation, tt.wantOp)
		}
		if ops.opTarget != tt.wantTgt {
			t.Errorf("protocols=%q: opTarget = %q, want %q", tt.protocols, ops.opTarget, tt.wantTgt)
		}
		if ops.opValue != tt.wantVal {
			t.Errorf("protocols=%q: opValue = %q, want %q", tt.protocols, ops.opValue, tt.wantVal)
		}
	}
}

func TestParseLDAPRelayOps_MaxDuration(t *testing.T) {
	params := sniffParams{
		ResponseIP: "dc01",
		Duration:   9999,
	}
	ops := parseLDAPRelayOps(params)
	if ops.duration != ldapRelayMaxDuration {
		t.Errorf("duration = %d, want %d (max)", ops.duration, ldapRelayMaxDuration)
	}
}

func TestLdapRelayDNToDomain(t *testing.T) {
	tests := []struct {
		dn   string
		want string
	}{
		{"DC=corp,DC=local", "corp.local"},
		{"DC=north,DC=sevenkingdoms,DC=local", "north.sevenkingdoms.local"},
		{"DC=ESSOS,DC=LOCAL", "ESSOS.LOCAL"},
		{"", ""},
	}
	for _, tt := range tests {
		got := ldapRelayDNToDomain(tt.dn)
		if got != tt.want {
			t.Errorf("ldapRelayDNToDomain(%q) = %q, want %q", tt.dn, got, tt.want)
		}
	}
}

func TestExecuteLDAPRelayCore_MissingTarget(t *testing.T) {
	task := structs.NewTask("ldap-test", "sniff", `{"action":"ldap-relay"}`)
	result := executeLDAPRelayCore(task)
	if result.Status != "error" {
		t.Fatalf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "target required") {
		t.Fatalf("expected target required error, got %q", result.Output)
	}
}

func TestLdapRelayConnInit(t *testing.T) {
	lc := &ldapRelayConn{msgID: 1}
	if lc.msgID != 1 {
		t.Errorf("msgID = %d, want 1", lc.msgID)
	}
}

func TestGenerateComputerPassword(t *testing.T) {
	pw := generateComputerPassword()
	if len(pw) != 16 {
		t.Errorf("password length = %d, want 16", len(pw))
	}
	pw2 := generateComputerPassword()
	if pw == pw2 {
		t.Error("two generated passwords should not be identical")
	}
}

func TestEncodeUnicodePwd(t *testing.T) {
	encoded := encodeUnicodePwd("Test123!")
	// unicodePwd = UTF-16LE("\"Test123!\"")
	// The quoted string is 10 chars → 20 bytes
	if len(encoded) != 20 {
		t.Errorf("encoded length = %d, want 20 (10 UTF-16LE chars)", len(encoded))
	}
	// First two bytes should be UTF-16LE for '"' (0x22, 0x00)
	if encoded[0] != 0x22 || encoded[1] != 0x00 {
		t.Errorf("first char = %02x%02x, want 2200 (UTF-16LE quote)", encoded[0], encoded[1])
	}
	// Last two bytes should also be '"'
	if encoded[18] != 0x22 || encoded[19] != 0x00 {
		t.Errorf("last char = %02x%02x, want 2200 (UTF-16LE quote)", encoded[18], encoded[19])
	}
}
