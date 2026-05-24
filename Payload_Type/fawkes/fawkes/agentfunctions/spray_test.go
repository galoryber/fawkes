package agentfunctions

import (
	"strings"
	"testing"
)

func TestCountSprayUsers_MultipleUsers(t *testing.T) {
	users := "admin\njsmith\nsvc_backup"
	if count := countSprayUsers(users); count != 3 {
		t.Errorf("expected 3 users, got %d", count)
	}
}

func TestCountSprayUsers_WithBlankLines(t *testing.T) {
	users := "admin\n\njsmith\n  \nsvc_backup\n"
	if count := countSprayUsers(users); count != 3 {
		t.Errorf("expected 3 users (blank lines skipped), got %d", count)
	}
}

func TestCountSprayUsers_Empty(t *testing.T) {
	if count := countSprayUsers(""); count != 0 {
		t.Errorf("expected 0 users, got %d", count)
	}
}

func TestCountSprayUsers_SingleUser(t *testing.T) {
	if count := countSprayUsers("admin"); count != 1 {
		t.Errorf("expected 1 user, got %d", count)
	}
}

func TestFormatSprayDisplay_Enumerate(t *testing.T) {
	msg := formatSprayDisplay("enumerate", "dc01", "corp.local", 5)
	if !strings.Contains(msg, "Enumerate users") {
		t.Errorf("expected 'Enumerate users', got %q", msg)
	}
	if !strings.Contains(msg, "dc01") || !strings.Contains(msg, "corp.local") || !strings.Contains(msg, "5 users") {
		t.Errorf("missing expected content in %q", msg)
	}
}

func TestFormatSprayDisplay_Kerberos(t *testing.T) {
	msg := formatSprayDisplay("kerberos", "dc01", "corp.local", 10)
	if !strings.Contains(msg, "Spray") {
		t.Errorf("expected 'Spray', got %q", msg)
	}
	if !strings.Contains(msg, "kerberos") {
		t.Errorf("expected 'kerberos' in message, got %q", msg)
	}
}

func TestFormatSprayDisplay_SMB(t *testing.T) {
	msg := formatSprayDisplay("smb", "10.0.0.1", "DOMAIN.COM", 3)
	if !strings.Contains(msg, "smb") || !strings.Contains(msg, "10.0.0.1") {
		t.Errorf("missing expected content in %q", msg)
	}
}

func TestFormatSprayArtifact_Enumerate(t *testing.T) {
	msg := formatSprayArtifact("enumerate", "dc01", 5)
	if !strings.Contains(msg, "Kerberos user enumeration") {
		t.Errorf("expected 'Kerberos user enumeration', got %q", msg)
	}
}

func TestFormatSprayArtifact_Spray(t *testing.T) {
	msg := formatSprayArtifact("ldap", "dc01", 10)
	if !strings.Contains(msg, "Password spray via ldap") {
		t.Errorf("expected 'Password spray via ldap', got %q", msg)
	}
	if !strings.Contains(msg, "10 users") {
		t.Errorf("expected '10 users', got %q", msg)
	}
}
