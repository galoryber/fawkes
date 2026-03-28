//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestMakeToken_Name(t *testing.T) {
	cmd := &MakeTokenCommand{}
	if got := cmd.Name(); got != "make-token" {
		t.Errorf("Name() = %q, want %q", got, "make-token")
	}
}

func TestMakeToken_ParamParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantDomain string
		wantUser   string
		wantPass   string
		wantLogon  int
	}{
		{
			"full params",
			`{"domain":"CORP","username":"admin","password":"P@ss","logon_type":9}`,
			"CORP", "admin", "P@ss", 9,
		},
		{
			"minimal params",
			`{"username":"user","password":"pw"}`,
			"", "user", "pw", 0,
		},
		{
			"interactive logon",
			`{"domain":"LOCAL","username":"user","password":"pw","logon_type":2}`,
			"LOCAL", "user", "pw", 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params MakeTokenParams
			if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if params.Domain != tt.wantDomain {
				t.Errorf("Domain = %q, want %q", params.Domain, tt.wantDomain)
			}
			if params.Username != tt.wantUser {
				t.Errorf("Username = %q, want %q", params.Username, tt.wantUser)
			}
			if params.Password != tt.wantPass {
				t.Errorf("Password = %q, want %q", params.Password, tt.wantPass)
			}
			if params.LogonType != tt.wantLogon {
				t.Errorf("LogonType = %d, want %d", params.LogonType, tt.wantLogon)
			}
		})
	}
}

func TestMakeToken_DomainDefault(t *testing.T) {
	// Test that empty domain defaults to "." in Execute logic
	var params MakeTokenParams
	json.Unmarshal([]byte(`{"username":"user","password":"pw"}`), &params)
	if params.Domain != "" {
		t.Fatalf("Pre-default domain should be empty, got %q", params.Domain)
	}
	// The default is applied in Execute(), verify the struct doesn't pre-populate
	// This is by design — Execute sets "." when domain is empty
}

func TestMakeToken_LogonTypeDefault(t *testing.T) {
	// Test that zero logon_type defaults to 9 (LOGON32_LOGON_NEW_CREDENTIALS)
	var params MakeTokenParams
	json.Unmarshal([]byte(`{"username":"user","password":"pw"}`), &params)
	if params.LogonType != 0 {
		t.Fatalf("Pre-default LogonType should be 0, got %d", params.LogonType)
	}
	// The default of 9 is applied in Execute()
}

func TestMakeToken_CredentialStruct(t *testing.T) {
	// Verify the credential output structure is correct
	var params MakeTokenParams
	json.Unmarshal([]byte(`{"domain":"CORP","username":"admin","password":"secret"}`), &params)

	if params.Domain != "CORP" || params.Username != "admin" || params.Password != "secret" {
		t.Error("Credential fields not parsed correctly")
	}
}
