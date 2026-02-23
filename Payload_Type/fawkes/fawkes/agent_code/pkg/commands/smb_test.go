package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSmbCommand_Name(t *testing.T) {
	cmd := &SmbCommand{}
	if cmd.Name() != "smb" {
		t.Errorf("expected name 'smb', got %q", cmd.Name())
	}
}

func TestSmbCommand_Description(t *testing.T) {
	cmd := &SmbCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(cmd.Description(), "T1021.002") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestSmbCommand_EmptyParams(t *testing.T) {
	cmd := &SmbCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestSmbCommand_InvalidJSON(t *testing.T) {
	cmd := &SmbCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestSmbCommand_MissingHost(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "shares",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing host, got %q", result.Status)
	}
}

func TestSmbCommand_MissingAction(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Host:     "192.0.2.1",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing action, got %q", result.Status)
	}
}

func TestSmbCommand_InvalidAction(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "invalid",
		Host:     "192.0.2.1",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unknown action") {
		t.Errorf("expected unknown action error, got %q", result.Output)
	}
}

func TestSmbCommand_LsMissingShare(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "ls",
		Host:     "192.0.2.1",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for ls without share, got %q", result.Status)
	}
}

func TestSmbCommand_CatMissingPath(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "cat",
		Host:     "192.0.2.1",
		Share:    "C$",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for cat without path, got %q", result.Status)
	}
}

func TestSmbCommand_UploadMissingContent(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "upload",
		Host:     "192.0.2.1",
		Share:    "C$",
		Path:     "test.txt",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for upload without content, got %q", result.Status)
	}
}

func TestSmbCommand_DomainParsing(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		domain         string
		expectedUser   string
		expectedDomain string
	}{
		{"DOMAIN\\user format", "DOMAIN\\user", "", "user", "DOMAIN"},
		{"user@domain format", "user@domain.local", "", "user", "domain.local"},
		{"explicit domain", "user", "MYDOMAIN", "user", "MYDOMAIN"},
		{"plain user", "plainuser", "", "plainuser", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := smbArgs{
				Username: tt.username,
				Domain:   tt.domain,
			}
			// Apply the same parsing logic as Execute
			if args.Domain == "" {
				if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
					args.Domain = parts[0]
					args.Username = parts[1]
				} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
					args.Domain = parts[1]
					args.Username = parts[0]
				}
			}
			if args.Username != tt.expectedUser {
				t.Errorf("username: got %q, want %q", args.Username, tt.expectedUser)
			}
			if args.Domain != tt.expectedDomain {
				t.Errorf("domain: got %q, want %q", args.Domain, tt.expectedDomain)
			}
		})
	}
}

func TestSmbCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("smb")
	if cmd == nil {
		t.Fatal("smb command not registered")
	}
	if cmd.Name() != "smb" {
		t.Errorf("expected name 'smb', got %q", cmd.Name())
	}
}
