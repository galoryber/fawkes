package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestShareHuntName(t *testing.T) {
	cmd := &ShareHuntCommand{}
	if cmd.Name() != "share-hunt" {
		t.Errorf("Expected 'share-hunt', got '%s'", cmd.Name())
	}
}

func TestShareHuntDescription(t *testing.T) {
	cmd := &ShareHuntCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestShareHuntBadJSON(t *testing.T) {
	cmd := &ShareHuntCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestShareHuntMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		args shareHuntArgs
	}{
		{"missing hosts", shareHuntArgs{Username: "admin", Password: "pass"}},
		{"missing username", shareHuntArgs{Hosts: "10.0.0.1", Password: "pass"}},
		{"missing password and hash", shareHuntArgs{Hosts: "10.0.0.1", Username: "admin"}},
	}

	cmd := &ShareHuntCommand{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params, _ := json.Marshal(tc.args)
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "error" {
				t.Errorf("Expected error, got %s: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, "required") {
				t.Errorf("Expected required fields error, got: %s", result.Output)
			}
		})
	}
}

func TestShareHuntTooManyHosts(t *testing.T) {
	cmd := &ShareHuntCommand{}
	params, _ := json.Marshal(shareHuntArgs{
		Hosts:    "10.0.0.0/22",
		Username: "admin",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for too many hosts")
	}
}

func TestShareHuntInvalidHosts(t *testing.T) {
	cmd := &ShareHuntCommand{}
	params, _ := json.Marshal(shareHuntArgs{
		Hosts:    "invalid/99",
		Username: "admin",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for invalid hosts")
	}
}

func TestShareHuntDomainParsingBackslash(t *testing.T) {
	cmd := &ShareHuntCommand{}
	params, _ := json.Marshal(shareHuntArgs{
		Hosts:    "127.0.0.1",
		Username: `CORP\admin`,
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Will fail to connect but should parse domain correctly
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestShareHuntDomainParsingUPN(t *testing.T) {
	cmd := &ShareHuntCommand{}
	params, _ := json.Marshal(shareHuntArgs{
		Hosts:    "127.0.0.1",
		Username: "admin@corp.local",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestShareHuntOutputFormat(t *testing.T) {
	cmd := &ShareHuntCommand{}
	params, _ := json.Marshal(shareHuntArgs{
		Hosts:    "127.0.0.1",
		Username: "admin",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if !strings.Contains(result.Output, "SHARE HUNT RESULTS") {
		t.Errorf("Expected header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "scanned") {
		t.Errorf("Expected summary, got: %s", result.Output)
	}
}

// --- shareHuntMatchFile tests ---

func TestShareHuntMatchFileHighValue(t *testing.T) {
	matchExts := shareHuntBuildExtSet("all")

	tests := []struct {
		filename string
		expected string
	}{
		{"passwords.txt", "HIGH-VALUE"},
		{"db_backup.sql", "HIGH-VALUE"},
		{"credentials.json", "HIGH-VALUE"},
		{"private_keys.pem", "HIGH-VALUE"},
		{"sam.bak", "HIGH-VALUE"},
	}

	for _, tc := range tests {
		result := shareHuntMatchFile(tc.filename, matchExts)
		if result != tc.expected {
			t.Errorf("shareHuntMatchFile(%s) = %s, want %s", tc.filename, result, tc.expected)
		}
	}
}

func TestShareHuntMatchFileExtension(t *testing.T) {
	matchExts := shareHuntBuildExtSet("all")

	tests := []struct {
		filename string
		expected string
	}{
		{"test.kdbx", "cred"},
		{"config.yaml", "config"},
		{"deploy.ps1", "code"},
		{"photo.jpg", ""},   // no match
		{"report.docx", ""}, // not in share-hunt patterns
	}

	for _, tc := range tests {
		result := shareHuntMatchFile(tc.filename, matchExts)
		if result != tc.expected {
			t.Errorf("shareHuntMatchFile(%s) = '%s', want '%s'", tc.filename, result, tc.expected)
		}
	}
}

func TestShareHuntMatchFileExactName(t *testing.T) {
	matchExts := shareHuntBuildExtSet("credentials")

	tests := []struct {
		filename string
		expected string
	}{
		{"id_rsa", "cred"},
		{"id_ed25519", "cred"},
		{".netrc", "cred"},
	}

	for _, tc := range tests {
		result := shareHuntMatchFile(tc.filename, matchExts)
		if result != tc.expected {
			t.Errorf("shareHuntMatchFile(%s) = '%s', want '%s'", tc.filename, result, tc.expected)
		}
	}
}

// --- shareHuntBuildExtSet tests ---

func TestShareHuntBuildExtSetAll(t *testing.T) {
	result := shareHuntBuildExtSet("all")
	// Should contain entries from all categories
	if _, ok := result[".kdbx"]; !ok {
		t.Error("Expected .kdbx in 'all' filter")
	}
	if _, ok := result[".yaml"]; !ok {
		t.Error("Expected .yaml in 'all' filter")
	}
	if _, ok := result[".ps1"]; !ok {
		t.Error("Expected .ps1 in 'all' filter")
	}
}

func TestShareHuntBuildExtSetCredentials(t *testing.T) {
	result := shareHuntBuildExtSet("credentials")
	if _, ok := result[".kdbx"]; !ok {
		t.Error("Expected .kdbx in credentials filter")
	}
	if _, ok := result[".yaml"]; ok {
		t.Error("Should NOT have .yaml in credentials filter")
	}
}

func TestShareHuntBuildExtSetConfigs(t *testing.T) {
	result := shareHuntBuildExtSet("configs")
	if _, ok := result[".yaml"]; !ok {
		t.Error("Expected .yaml in configs filter")
	}
	if _, ok := result[".kdbx"]; ok {
		t.Error("Should NOT have .kdbx in configs filter")
	}
}

func TestShareHuntBuildExtSetCode(t *testing.T) {
	result := shareHuntBuildExtSet("code")
	if _, ok := result[".ps1"]; !ok {
		t.Error("Expected .ps1 in code filter")
	}
	if _, ok := result[".kdbx"]; ok {
		t.Error("Should NOT have .kdbx in code filter")
	}
}

func TestShareHuntCancellation(t *testing.T) {
	task := structs.NewTask("cancel-hunt", "share-hunt", "")
	task.SetStop()

	cmd := &ShareHuntCommand{}
	params, _ := json.Marshal(shareHuntArgs{
		Hosts:    "127.0.0.1,127.0.0.2",
		Username: "admin",
		Password: "pass",
	})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}
