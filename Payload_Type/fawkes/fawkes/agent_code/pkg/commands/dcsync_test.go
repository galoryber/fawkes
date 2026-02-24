package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDcsyncName(t *testing.T) {
	cmd := &DcsyncCommand{}
	if cmd.Name() != "dcsync" {
		t.Fatalf("expected 'dcsync', got %q", cmd.Name())
	}
}

func TestDcsyncEmptyParams(t *testing.T) {
	cmd := &DcsyncCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error for empty params, got %q", result.Status)
	}
}

func TestDcsyncBadJSON(t *testing.T) {
	cmd := &DcsyncCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Fatalf("expected error for bad JSON, got %q", result.Status)
	}
}

func TestDcsyncMissingServer(t *testing.T) {
	args := dcsyncArgs{Username: "admin", Password: "pass", Target: "Administrator"}
	b, _ := json.Marshal(args)
	cmd := &DcsyncCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing server, got %q", result.Status)
	}
}

func TestDcsyncMissingCredentials(t *testing.T) {
	args := dcsyncArgs{Server: "dc01", Username: "admin", Target: "Administrator"}
	b, _ := json.Marshal(args)
	cmd := &DcsyncCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing credentials, got %q", result.Status)
	}
}

func TestDcsyncMissingTarget(t *testing.T) {
	args := dcsyncArgs{Server: "dc01", Username: "admin", Password: "pass"}
	b, _ := json.Marshal(args)
	cmd := &DcsyncCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing target, got %q", result.Status)
	}
}

func TestDcsyncHashAccepted(t *testing.T) {
	// With hash instead of password — should pass validation but fail on network connect
	args := dcsyncArgs{Server: "dc01", Username: "admin", Hash: "aad3b435b51404ee:8846f7eaee8fb117", Target: "Administrator"}
	b, _ := json.Marshal(args)
	cmd := &DcsyncCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should fail on network connect, not on validation
	if result.Status != "error" {
		t.Fatalf("expected error (network), got %q", result.Status)
	}
	if result.Output == "Error: server, username, and password (or hash) are required" {
		t.Fatal("hash should be accepted as credential")
	}
}

func TestDcsyncDomainParsing(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		domain         string
		expectDomain   string
		expectUsername string
	}{
		{"backslash format", `CORP\admin`, "", "CORP", "admin"},
		{"UPN format", "admin@corp.local", "", "corp.local", "admin"},
		{"explicit domain", "admin", "CORP.LOCAL", "CORP.LOCAL", "admin"},
		{"no domain", "admin", "", "", "admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := dcsyncArgs{
				Server:   "dc01",
				Username: tt.username,
				Password: "pass",
				Domain:   tt.domain,
				Target:   "Administrator",
			}

			// Parse domain same way Execute does
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

func TestDcsyncTargetParsing(t *testing.T) {
	tests := []struct {
		target string
		count  int
	}{
		{"Administrator", 1},
		{"Administrator,krbtgt", 2},
		{"admin, krbtgt, svc_backup", 3},
		{" , , ", 0},
	}

	for _, tt := range tests {
		targets := []string{}
		for _, t := range strings.Split(tt.target, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				targets = append(targets, t)
			}
		}
		if len(targets) != tt.count {
			t.Errorf("target %q: got %d targets, want %d", tt.target, len(targets), tt.count)
		}
	}
}
