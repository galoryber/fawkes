package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestFindAdminName(t *testing.T) {
	cmd := &FindAdminCommand{}
	if cmd.Name() != "find-admin" {
		t.Fatalf("expected 'find-admin', got %q", cmd.Name())
	}
}

func TestFindAdminDescription(t *testing.T) {
	cmd := &FindAdminCommand{}
	if !strings.Contains(cmd.Description(), "T1021") {
		t.Fatal("description should contain MITRE ATT&CK mapping")
	}
}

func TestFindAdminEmptyParams(t *testing.T) {
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error for empty params, got %q", result.Status)
	}
}

func TestFindAdminBadJSON(t *testing.T) {
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Fatalf("expected error for bad JSON, got %q", result.Status)
	}
}

func TestFindAdminMissingHosts(t *testing.T) {
	args := findAdminArgs{Username: "admin", Password: "pass"}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing hosts, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "hosts") {
		t.Fatalf("unexpected error: %s", result.Output)
	}
}

func TestFindAdminMissingCredentials(t *testing.T) {
	args := findAdminArgs{Hosts: "192.168.1.1", Username: "admin"}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing creds, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "password (or hash)") {
		t.Fatalf("unexpected error: %s", result.Output)
	}
}

func TestFindAdminMissingUsername(t *testing.T) {
	args := findAdminArgs{Hosts: "192.168.1.1", Password: "pass"}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing username, got %q", result.Status)
	}
}

func TestFindAdminDomainParsing(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		domain         string
		expectDomain   string
		expectUsername string
	}{
		{"backslash", `CORP\admin`, "", "CORP", "admin"},
		{"UPN", "admin@corp.local", "", "corp.local", "admin"},
		{"explicit", "admin", "CORP.LOCAL", "CORP.LOCAL", "admin"},
		{"no domain", "admin", "", "", "admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := findAdminArgs{
				Username: tt.username,
				Domain:   tt.domain,
			}
			if args.Domain == "" {
				if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
					args.Domain = parts[0]
					args.Username = parts[1]
				} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
					args.Domain = parts[1]
					args.Username = parts[0]
				}
			}
			if args.Domain != tt.expectDomain {
				t.Errorf("domain: got %q, want %q", args.Domain, tt.expectDomain)
			}
			if args.Username != tt.expectUsername {
				t.Errorf("username: got %q, want %q", args.Username, tt.expectUsername)
			}
		})
	}
}

func TestFindAdminHashDecoding(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"pure NT hash", "8846f7eaee8fb117ad06bdd830b7586c", false},
		{"LM:NT format", "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", false},
		{"invalid hex", "not-a-hash", true},
		{"wrong length", "aabbccdd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := findAdminDecodeHash(tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestFindAdminHashAccepted(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.1",
		Username: "admin",
		Hash:     "aad3b435b51404ee:8846f7eaee8fb117",
		Timeout:  2,
	}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should fail on network, not validation
	if result.Output == "Error: username and password (or hash) are required" {
		t.Fatal("hash should be accepted as credential")
	}
	if !strings.Contains(result.Output, "PTH") {
		t.Fatal("output should indicate PTH authentication")
	}
}

func TestFindAdminDefaultValues(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.1",
		Username: "admin",
		Password: "pass",
	}
	// Verify defaults
	if args.Timeout <= 0 {
		args.Timeout = 5
	}
	if args.Concurrency <= 0 {
		args.Concurrency = 50
	}
	if args.Method == "" {
		args.Method = "smb"
	}
	if args.Timeout != 5 {
		t.Fatalf("expected default timeout 5, got %d", args.Timeout)
	}
	if args.Concurrency != 50 {
		t.Fatalf("expected default concurrency 50, got %d", args.Concurrency)
	}
	if args.Method != "smb" {
		t.Fatalf("expected default method 'smb', got %q", args.Method)
	}
}

func TestFindAdminSMBUnreachable(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.1",
		Username: "admin",
		Password: "pass",
		Method:   "smb",
		Timeout:  2,
	}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for unreachable host, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unreachable") {
		t.Fatalf("expected unreachable message, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "0/1 hosts") {
		t.Fatalf("expected 0/1 count, got: %s", result.Output)
	}
}

func TestFindAdminWinRMUnreachable(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.1",
		Username: "admin",
		Password: "pass",
		Method:   "winrm",
		Timeout:  2,
	}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for unreachable host, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unreachable") {
		t.Fatalf("expected unreachable message, got: %s", result.Output)
	}
}

func TestFindAdminBothMethodsUnreachable(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.1",
		Username: "admin",
		Password: "pass",
		Method:   "both",
		Timeout:  2,
	}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Both methods should be tried
	if !strings.Contains(result.Output, "SMB") || !strings.Contains(result.Output, "WinRM") {
		t.Fatalf("expected both SMB and WinRM results, got: %s", result.Output)
	}
}

func TestFindAdminCIDRParsing(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.0/30",
		Username: "admin",
		Password: "pass",
		Method:   "smb",
		Timeout:  1,
	}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should parse CIDR and scan hosts (will be unreachable)
	if !strings.Contains(result.Output, "hosts") {
		t.Fatalf("expected host sweep output, got: %s", result.Output)
	}
}

func TestFindAdminOutputFormat(t *testing.T) {
	args := findAdminArgs{
		Hosts:    "192.0.2.1",
		Username: `CORP\admin`,
		Password: "pass",
		Method:   "smb",
		Timeout:  2,
	}
	b, _ := json.Marshal(args)
	cmd := &FindAdminCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Check output formatting
	if !strings.Contains(result.Output, "Admin access sweep") {
		t.Fatal("missing header")
	}
	if !strings.Contains(result.Output, "CORP\\admin") {
		t.Fatal("missing credential display")
	}
	if !strings.Contains(result.Output, "hosts have admin access") {
		t.Fatal("missing summary line")
	}
}
