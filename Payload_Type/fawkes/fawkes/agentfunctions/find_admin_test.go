package agentfunctions

import (
	"testing"
)

func TestParseFindAdminResults_MixedResults(t *testing.T) {
	input := `[{"host":"192.168.1.1","method":"smb","admin":true},{"host":"192.168.1.2","method":"smb","admin":false},{"host":"192.168.1.3","method":"wmi","admin":true}]`

	admins := parseFindAdminResults(input)
	if len(admins) != 2 {
		t.Fatalf("expected 2 admin hosts, got %d", len(admins))
	}
	if admins[0].Host != "192.168.1.1" {
		t.Errorf("expected host 192.168.1.1, got %q", admins[0].Host)
	}
	if admins[0].Method != "smb" {
		t.Errorf("expected method smb, got %q", admins[0].Method)
	}
	if admins[1].Host != "192.168.1.3" {
		t.Errorf("expected host 192.168.1.3, got %q", admins[1].Host)
	}
	if admins[1].Method != "wmi" {
		t.Errorf("expected method wmi, got %q", admins[1].Method)
	}
}

func TestParseFindAdminResults_NoAdmins(t *testing.T) {
	input := `[{"host":"10.0.0.1","method":"smb","admin":false},{"host":"10.0.0.2","method":"smb","admin":false}]`

	admins := parseFindAdminResults(input)
	if len(admins) != 0 {
		t.Errorf("expected 0 admin hosts, got %d", len(admins))
	}
}

func TestParseFindAdminResults_EmptyArray(t *testing.T) {
	admins := parseFindAdminResults("[]")
	if admins != nil {
		t.Errorf("expected nil for empty array, got %v", admins)
	}
}

func TestParseFindAdminResults_EmptyString(t *testing.T) {
	admins := parseFindAdminResults("")
	if admins != nil {
		t.Errorf("expected nil for empty string, got %v", admins)
	}
}

func TestParseFindAdminResults_InvalidJSON(t *testing.T) {
	admins := parseFindAdminResults("not json")
	if admins != nil {
		t.Errorf("expected nil for invalid JSON, got %v", admins)
	}
}

func TestParseFindAdminResults_AllAdmins(t *testing.T) {
	input := `[{"host":"dc01","method":"smb","admin":true},{"host":"dc02","method":"wmi","admin":true}]`

	admins := parseFindAdminResults(input)
	if len(admins) != 2 {
		t.Fatalf("expected 2 admin hosts, got %d", len(admins))
	}
}

func TestParseFindAdminResults_SingleHost(t *testing.T) {
	input := `[{"host":"web01","method":"smb","admin":true}]`

	admins := parseFindAdminResults(input)
	if len(admins) != 1 {
		t.Fatalf("expected 1 admin host, got %d", len(admins))
	}
	if admins[0].Host != "web01" {
		t.Errorf("expected web01, got %q", admins[0].Host)
	}
}
