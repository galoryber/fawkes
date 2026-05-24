package agentfunctions

import (
	"testing"
)

func TestParseKeychainCredentials_ValidEntry(t *testing.T) {
	input := `keychain: "/Users/admin/Library/Keychains/login.keychain-db"
    "acct"<blob>="admin@corp.com"
    "svce"<blob>="Wi-Fi"
password: "SuperSecret123"`

	creds := parseKeychainCredentials(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Account != "admin@corp.com" {
		t.Errorf("expected admin@corp.com, got %q", creds[0].Account)
	}
	if creds[0].Service != "Wi-Fi" {
		t.Errorf("expected Wi-Fi, got %q", creds[0].Service)
	}
	if creds[0].Pass != "SuperSecret123" {
		t.Errorf("expected SuperSecret123, got %q", creds[0].Pass)
	}
}

func TestParseKeychainCredentials_ServerField(t *testing.T) {
	input := `    "acct"<blob>="jsmith"
    "srvr"<blob>="github.com"
password: "ghp_token123"`

	creds := parseKeychainCredentials(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Service != "github.com" {
		t.Errorf("expected github.com, got %q", creds[0].Service)
	}
}

func TestParseKeychainCredentials_HexPasswordSkipped(t *testing.T) {
	input := `    "acct"<blob>="admin"
    "svce"<blob>="Chrome Safe Storage"
password: 0xDEADBEEF`

	creds := parseKeychainCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (hex password filtered), got %d", len(creds))
	}
}

func TestParseKeychainCredentials_EmptyPassword(t *testing.T) {
	input := `    "acct"<blob>="user"
    "svce"<blob>="service"
password: ""`

	creds := parseKeychainCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (empty password), got %d", len(creds))
	}
}

func TestParseKeychainCredentials_NoAccount(t *testing.T) {
	input := `    "svce"<blob>="service"
password: "secret"`

	creds := parseKeychainCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (no account), got %d", len(creds))
	}
}

func TestParseKeychainCredentials_MultipleEntries(t *testing.T) {
	input := `    "acct"<blob>="user1"
    "svce"<blob>="svc1"
password: "pass1"
    "acct"<blob>="user2"
    "svce"<blob>="svc2"
password: "pass2"`

	creds := parseKeychainCredentials(input)
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
}

func TestParseKeychainCredentials_Empty(t *testing.T) {
	creds := parseKeychainCredentials("")
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}
