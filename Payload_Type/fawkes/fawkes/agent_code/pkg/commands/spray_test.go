package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSprayName(t *testing.T) {
	cmd := &SprayCommand{}
	if cmd.Name() != "spray" {
		t.Errorf("expected 'spray', got '%s'", cmd.Name())
	}
}

func TestSprayDescription(t *testing.T) {
	cmd := &SprayCommand{}
	if !strings.Contains(cmd.Description(), "T1110.003") {
		t.Error("description should contain MITRE technique")
	}
}

func TestSprayEmptyParams(t *testing.T) {
	cmd := &SprayCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}
}

func TestSprayInvalidJSON(t *testing.T) {
	cmd := &SprayCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("invalid JSON should return error")
	}
}

func TestSprayMissingServer(t *testing.T) {
	cmd := &SprayCommand{}
	args := sprayArgs{
		Domain:   "CORP.LOCAL",
		Users:    "user1",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "server") {
		t.Error("missing server should return error")
	}
}

func TestSprayMissingDomain(t *testing.T) {
	cmd := &SprayCommand{}
	args := sprayArgs{
		Server:   "dc01",
		Users:    "user1",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "domain") {
		t.Error("missing domain should return error")
	}
}

func TestSprayMissingUsers(t *testing.T) {
	cmd := &SprayCommand{}
	args := sprayArgs{
		Server:   "dc01",
		Domain:   "CORP.LOCAL",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "users") {
		t.Error("missing users should return error")
	}
}

func TestSprayMissingPassword(t *testing.T) {
	cmd := &SprayCommand{}
	args := sprayArgs{
		Server: "dc01",
		Domain: "CORP.LOCAL",
		Users:  "user1",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "password") {
		t.Error("missing password should return error")
	}
}

func TestSprayUnknownAction(t *testing.T) {
	cmd := &SprayCommand{}
	args := sprayArgs{
		Action:   "ftp",
		Server:   "dc01",
		Domain:   "CORP.LOCAL",
		Users:    "user1",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("unknown action should return error, got: %s", result.Output)
	}
}

func TestParseSprayUsers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"single user", "user1", 1},
		{"multiple users", "user1\nuser2\nuser3", 3},
		{"with blanks", "user1\n\nuser2\n\n", 2},
		{"with whitespace", "  user1  \n  user2  ", 2},
		{"empty", "", 0},
		{"only whitespace", "  \n  \n  ", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := parseSprayUsers(tt.input)
			if len(users) != tt.expected {
				t.Errorf("expected %d users, got %d", tt.expected, len(users))
			}
		})
	}
}

func TestParseSprayUsersTrimsWhitespace(t *testing.T) {
	users := parseSprayUsers("  alice  \n  bob  ")
	if users[0] != "alice" || users[1] != "bob" {
		t.Errorf("expected trimmed users, got %v", users)
	}
}

func TestClassifyKrbError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"preauth failed", "KDC_ERR_PREAUTH_FAILED", "wrong password"},
		{"error code 24", "error_code: 24", "wrong password"},
		{"principal unknown", "KDC_ERR_C_PRINCIPAL_UNKNOWN", "doesn't exist"},
		{"error code 6", "error_code: 6", "doesn't exist"},
		{"client revoked", "KDC_ERR_CLIENT_REVOKED", "REVOKED"},
		{"error code 18", "error_code: 18", "REVOKED"},
		{"key expired", "KDC_ERR_KEY_EXPIRED", "expired"},
		{"error code 23", "error_code: 23", "expired"},
		{"policy", "KDC_ERR_POLICY", "Policy"},
		{"unknown error", "some other error", "Error:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyKrbError(stringError(tt.errMsg))
			if !strings.Contains(result, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, result)
			}
		})
	}
}

func TestClassifyLDAPError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"invalid creds", "LDAP Result Code 49: data 52e", "wrong password"},
		{"user not found", "LDAP Result Code 49: data 525", "not found"},
		{"locked", "LDAP Result Code 49: data 775", "locked"},
		{"disabled", "LDAP Result Code 49: data 533", "disabled"},
		{"expired", "LDAP Result Code 49: data 532", "expired"},
		{"account expired", "LDAP Result Code 49: data 701", "expired"},
		{"must change", "LDAP Result Code 49: data 773", "change password"},
		{"unknown", "some error", "Error:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyLDAPError(stringError(tt.errMsg))
			if !strings.Contains(result, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, result)
			}
		})
	}
}

func TestClassifySMBError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		contains string
	}{
		{"logon failure", "STATUS_LOGON_FAILURE", "wrong password"},
		{"locked", "STATUS_ACCOUNT_LOCKED_OUT", "locked"},
		{"disabled", "STATUS_ACCOUNT_DISABLED", "disabled"},
		{"expired", "STATUS_PASSWORD_EXPIRED", "expired"},
		{"must change", "STATUS_PASSWORD_MUST_CHANGE", "change password"},
		{"restriction", "STATUS_ACCOUNT_RESTRICTION", "restriction"},
		{"unknown", "some error", "Error:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySMBError(stringError(tt.errMsg))
			if !strings.Contains(result, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, result)
			}
		})
	}
}

func TestSprayFormatResults(t *testing.T) {
	args := sprayArgs{
		Server:   "dc01",
		Domain:   "CORP.LOCAL",
		Password: "Summer2026!",
		Delay:    1000,
		Jitter:   25,
	}
	users := []string{"user1", "user2", "user3"}
	results := []sprayResult{
		{Username: "user1", Success: true, Message: "Authentication successful"},
		{Username: "user2", Success: false, Message: "Pre-auth failed (wrong password)"},
		{Username: "user3", Success: false, Message: "Account locked out"},
	}

	cmdResult := sprayFormatResults("kerberos", args, users, results)
	if cmdResult.Status != "success" {
		t.Error("expected success status")
	}
	if !strings.Contains(cmdResult.Output, "VALID: user1") {
		t.Error("expected VALID label for successful auth")
	}
	if !strings.Contains(cmdResult.Output, "LOCKED: user3") {
		t.Error("expected LOCKED label for locked account")
	}
	if !strings.Contains(cmdResult.Output, "1 valid") {
		t.Error("expected valid count in summary")
	}
	if !strings.Contains(cmdResult.Output, "1 locked") {
		t.Error("expected locked count in summary")
	}
	if !strings.Contains(cmdResult.Output, "Delay: 1000ms") {
		t.Error("expected delay info")
	}
	if !strings.Contains(cmdResult.Output, "jitter: 25%") {
		t.Error("expected jitter info")
	}
}

func TestSprayDefaultAction(t *testing.T) {
	// When action is empty, should default to "kerberos"
	// This will fail to connect but shouldn't error on action validation
	cmd := &SprayCommand{}
	args := sprayArgs{
		Server:   "192.0.2.1", // RFC 5737 test address
		Domain:   "TEST.LOCAL",
		Users:    "testuser",
		Password: "testpass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	// Should attempt kerberos (will fail on connection, not action)
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("empty action should default to kerberos, not return unknown action error")
	}
}

// stringError is a simple error type for testing
type stringError string

func (e stringError) Error() string { return string(e) }
