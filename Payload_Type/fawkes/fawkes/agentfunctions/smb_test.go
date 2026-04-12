package agentfunctions

import (
	"testing"
)

// --- parseSMBExfilResult tests ---

func TestParseSMBExfilResult_ValidJSON(t *testing.T) {
	input := `{"host":"192.168.1.10","share":"ADMIN$","remote_path":"Windows\\Temp","filename":"payload.exe","total_size":1234,"success":true}`

	result := parseSMBExfilResult(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Host != "192.168.1.10" {
		t.Errorf("expected host 192.168.1.10, got %q", result.Host)
	}
	if result.Share != "ADMIN$" {
		t.Errorf("expected share ADMIN$, got %q", result.Share)
	}
	if result.TotalSize != 1234 {
		t.Errorf("expected size 1234, got %d", result.TotalSize)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestParseSMBExfilResult_InvalidJSON(t *testing.T) {
	result := parseSMBExfilResult("not json")
	if result != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestParseSMBExfilResult_EmptyHost(t *testing.T) {
	result := parseSMBExfilResult(`{"host":"","share":"C$","success":true}`)
	if result != nil {
		t.Error("expected nil for empty host")
	}
}

func TestParseSMBExfilResult_FailedExfil(t *testing.T) {
	input := `{"host":"10.0.0.1","share":"IPC$","filename":"test.txt","total_size":0,"success":false}`
	result := parseSMBExfilResult(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Success {
		t.Error("expected success=false")
	}
}

// --- parseSMBShareLines tests ---

func TestParseSMBShareLines_ValidOutput(t *testing.T) {
	input := `Shares on 192.168.1.10:
  ADMIN$ (Admin)
  C$ (Default)
  IPC$ (Remote IPC)
Shares on 192.168.1.11:
  SYSVOL (Logon)
  NETLOGON (Logon)`

	shares := parseSMBShareLines(input)
	if len(shares) != 2 {
		t.Fatalf("expected 2 share lines, got %d", len(shares))
	}
	if shares[0] != "Shares on 192.168.1.10:" {
		t.Errorf("expected 'Shares on 192.168.1.10:', got %q", shares[0])
	}
	if shares[1] != "Shares on 192.168.1.11:" {
		t.Errorf("expected 'Shares on 192.168.1.11:', got %q", shares[1])
	}
}

func TestParseSMBShareLines_NoSharesKeyword(t *testing.T) {
	shares := parseSMBShareLines("Some random output")
	if len(shares) != 0 {
		t.Errorf("expected 0 share lines, got %d", len(shares))
	}
}

func TestParseSMBShareLines_EmptyInput(t *testing.T) {
	shares := parseSMBShareLines("")
	if len(shares) != 0 {
		t.Errorf("expected 0 share lines, got %d", len(shares))
	}
}

func TestParseSMBShareLines_SMBKeywordOnly(t *testing.T) {
	input := `SMB connection established
No shares found`
	shares := parseSMBShareLines(input)
	if len(shares) != 0 {
		t.Errorf("expected 0 share lines (no 'Shares on'), got %d", len(shares))
	}
}
