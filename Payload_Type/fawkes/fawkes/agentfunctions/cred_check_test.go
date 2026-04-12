package agentfunctions

import (
	"testing"
)

func TestParseCredCheckSuccesses_ValidLines(t *testing.T) {
	input := `192.168.1.1 | SMB | SUCCESS | admin
192.168.1.2 | LDAP | FAILED | admin
192.168.1.3 | WinRM | SUCCESS | admin`

	results := parseCredCheckSuccesses(input)
	if len(results) != 2 {
		t.Fatalf("expected 2 successes, got %d", len(results))
	}
	if results[0].Host != "192.168.1.1" {
		t.Errorf("expected host 192.168.1.1, got %q", results[0].Host)
	}
	if results[0].Protocol != "SMB" {
		t.Errorf("expected protocol SMB, got %q", results[0].Protocol)
	}
	if results[1].Host != "192.168.1.3" {
		t.Errorf("expected host 192.168.1.3, got %q", results[1].Host)
	}
	if results[1].Protocol != "WinRM" {
		t.Errorf("expected protocol WinRM, got %q", results[1].Protocol)
	}
}

func TestParseCredCheckSuccesses_NoSuccesses(t *testing.T) {
	input := `192.168.1.1 | SMB | FAILED | admin
192.168.1.2 | LDAP | FAILED | admin`

	results := parseCredCheckSuccesses(input)
	if len(results) != 0 {
		t.Errorf("expected 0 successes, got %d", len(results))
	}
}

func TestParseCredCheckSuccesses_EmptyInput(t *testing.T) {
	results := parseCredCheckSuccesses("")
	if len(results) != 0 {
		t.Errorf("expected 0 results from empty input, got %d", len(results))
	}
}

func TestParseCredCheckSuccesses_NoPipeDelimiter(t *testing.T) {
	input := "SUCCESS: login worked on host1"
	results := parseCredCheckSuccesses(input)
	if len(results) != 0 {
		t.Errorf("expected 0 results (no pipe delimiter), got %d", len(results))
	}
}

func TestParseCredCheckSuccesses_MixedOutput(t *testing.T) {
	input := `Credential check started...
10.0.0.1 | SMB | SUCCESS | domain\admin
10.0.0.2 | LDAP | ERROR | timeout
Some status message
10.0.0.3 | MSSQL | SUCCESS | sa`

	results := parseCredCheckSuccesses(input)
	if len(results) != 2 {
		t.Fatalf("expected 2 successes, got %d", len(results))
	}
	if results[0].Host != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", results[0].Host)
	}
	if results[1].Protocol != "MSSQL" {
		t.Errorf("expected MSSQL, got %q", results[1].Protocol)
	}
}

func TestParseCredCheckSuccesses_InsufficientParts(t *testing.T) {
	input := "host | SUCCESS"
	results := parseCredCheckSuccesses(input)
	if len(results) != 0 {
		t.Errorf("expected 0 results (< 3 parts), got %d", len(results))
	}
}
