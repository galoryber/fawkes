package agentfunctions

import (
	"testing"
)

func TestParseBrowserCredentials_SingleBlock(t *testing.T) {
	input := `=== Browser Credentials ===
Browser: Chrome
URL: https://example.com/login
Username: admin
Password: secret123`

	creds := parseBrowserCredentials(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Browser != "Chrome" {
		t.Errorf("expected Chrome, got %q", creds[0].Browser)
	}
	if creds[0].URL != "https://example.com/login" {
		t.Errorf("expected URL, got %q", creds[0].URL)
	}
	if creds[0].Username != "admin" {
		t.Errorf("expected admin, got %q", creds[0].Username)
	}
	if creds[0].Password != "secret123" {
		t.Errorf("expected secret123, got %q", creds[0].Password)
	}
}

func TestParseBrowserCredentials_MultipleBlocks(t *testing.T) {
	input := `=== Browser Credentials ===
Browser: Chrome
URL: https://site1.com
Username: user1
Password: pass1
Browser: Edge
URL: https://site2.com
Username: user2
Password: pass2`

	creds := parseBrowserCredentials(input)
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	if creds[0].Browser != "Chrome" {
		t.Errorf("expected Chrome for first, got %q", creds[0].Browser)
	}
	if creds[1].Browser != "Edge" {
		t.Errorf("expected Edge for second, got %q", creds[1].Browser)
	}
}

func TestParseBrowserCredentials_MissingPassword(t *testing.T) {
	input := `Browser: Chrome
URL: https://example.com
Username: admin`

	creds := parseBrowserCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (missing password), got %d", len(creds))
	}
}

func TestParseBrowserCredentials_MissingUsername(t *testing.T) {
	input := `Browser: Chrome
URL: https://example.com
Password: secret`

	creds := parseBrowserCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (missing username), got %d", len(creds))
	}
}

func TestParseBrowserCredentials_EmptyInput(t *testing.T) {
	creds := parseBrowserCredentials("")
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}

func TestParseBrowserCredentials_IncompleteFirstBlock(t *testing.T) {
	input := `Browser: Firefox
URL: https://old.com
Browser: Chrome
URL: https://new.com
Username: admin
Password: pass`

	creds := parseBrowserCredentials(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (first block incomplete), got %d", len(creds))
	}
	if creds[0].Browser != "Chrome" {
		t.Errorf("expected Chrome, got %q", creds[0].Browser)
	}
}
