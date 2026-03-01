package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCredCheckName(t *testing.T) {
	cmd := &CredCheckCommand{}
	if cmd.Name() != "cred-check" {
		t.Errorf("Expected 'cred-check', got '%s'", cmd.Name())
	}
}

func TestCredCheckDescription(t *testing.T) {
	cmd := &CredCheckCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestCredCheckBadJSON(t *testing.T) {
	cmd := &CredCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestCredCheckMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		args credCheckArgs
	}{
		{"missing hosts", credCheckArgs{Username: "admin", Password: "pass"}},
		{"missing username", credCheckArgs{Hosts: "10.0.0.1", Password: "pass"}},
		{"missing password and hash", credCheckArgs{Hosts: "10.0.0.1", Username: "admin"}},
	}

	cmd := &CredCheckCommand{}
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

func TestCredCheckTooManyHosts(t *testing.T) {
	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "10.0.0.0/22",
		Username: "admin",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for too many hosts")
	}
	if !strings.Contains(result.Output, "too many hosts") {
		t.Errorf("Expected too many hosts error, got: %s", result.Output)
	}
}

func TestCredCheckInvalidHosts(t *testing.T) {
	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "invalid/99",
		Username: "admin",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for invalid hosts")
	}
}

func TestCredCheckDomainParsing(t *testing.T) {
	// Test backslash format
	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "127.0.0.1",
		Username: `DOMAIN\admin`,
		Password: "pass",
		Timeout:  1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, `DOMAIN\admin`) {
		t.Errorf("Expected DOMAIN\\admin in output, got: %s", result.Output)
	}
}

func TestCredCheckUPNFormat(t *testing.T) {
	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "127.0.0.1",
		Username: "admin@domain.local",
		Password: "pass",
		Timeout:  1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, `domain.local\admin`) {
		t.Errorf("Expected parsed domain in output, got: %s", result.Output)
	}
}

func TestCredCheckUnreachableHost(t *testing.T) {
	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "127.0.0.1",
		Username: "admin",
		Password: "pass",
		Timeout:  1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "CREDENTIAL CHECK") {
		t.Errorf("Expected header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 host(s) checked") {
		t.Errorf("Expected 1 host checked, got: %s", result.Output)
	}
}

func TestCredCheckHashProvided(t *testing.T) {
	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "127.0.0.1",
		Username: "admin",
		Hash:     "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
		Timeout:  1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should not error on hash (even if auth fails, output should be formatted)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}

// --- BER encoding tests ---

func TestCredCheckBuildLDAPBind(t *testing.T) {
	// Verify the LDAP bind request is well-formed
	data := credCheckBuildLDAPBind(1, "user@domain.local", "password123")
	if len(data) == 0 {
		t.Fatal("Expected non-empty LDAP bind request")
	}
	// Should start with SEQUENCE tag (0x30)
	if data[0] != 0x30 {
		t.Errorf("Expected SEQUENCE tag 0x30, got 0x%02x", data[0])
	}
}

func TestCredCheckBERString(t *testing.T) {
	result := credCheckBERString(0x04, "hello")
	if len(result) != 7 { // tag(1) + len(1) + data(5)
		t.Errorf("Expected 7 bytes, got %d", len(result))
	}
	if result[0] != 0x04 {
		t.Errorf("Expected tag 0x04, got 0x%02x", result[0])
	}
	if result[1] != 5 {
		t.Errorf("Expected length 5, got %d", result[1])
	}
	if string(result[2:]) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(result[2:]))
	}
}

func TestCredCheckBERWrapShort(t *testing.T) {
	data := []byte{1, 2, 3}
	result := credCheckBERWrap(0x30, data)
	// tag(1) + short length(1) + data(3) = 5
	if len(result) != 5 {
		t.Errorf("Expected 5 bytes, got %d", len(result))
	}
}

func TestCredCheckBERWrapLong(t *testing.T) {
	// Test with data > 127 bytes
	data := make([]byte, 200)
	result := credCheckBERWrap(0x30, data)
	// tag(1) + long length(2) + data(200) = 203
	if len(result) < 203 {
		t.Errorf("Expected at least 203 bytes, got %d", len(result))
	}
}

func TestCredCheckBEREncodeLength(t *testing.T) {
	tests := []struct {
		length int
		bytes  int // expected encoded length in bytes
	}{
		{0, 1},
		{127, 1},
		{128, 2}, // 0x81 0x80
		{255, 2}, // 0x81 0xFF
		{256, 3}, // 0x82 0x01 0x00
	}

	for _, tc := range tests {
		result := credCheckBEREncodeLength(tc.length)
		if len(result) != tc.bytes {
			t.Errorf("credCheckBEREncodeLength(%d): expected %d bytes, got %d: %v", tc.length, tc.bytes, len(result), result)
		}
	}
}

func TestCredCheckParseLDAPBindResponse(t *testing.T) {
	// Test with too short data
	if credCheckParseLDAPBindResponse([]byte{0x30}) != -1 {
		t.Error("Expected -1 for short data")
	}

	// Test with invalid outer tag
	if credCheckParseLDAPBindResponse(make([]byte, 20)) != -1 {
		t.Error("Expected -1 for non-SEQUENCE outer tag")
	}
}

func TestCredCheckBERDecodeLength(t *testing.T) {
	// Empty input
	length, skip := credCheckBERDecodeLength([]byte{})
	if length != 0 || skip != 0 {
		t.Errorf("Expected (0,0) for empty, got (%d,%d)", length, skip)
	}

	// Short form
	length, skip = credCheckBERDecodeLength([]byte{42})
	if length != 42 || skip != 1 {
		t.Errorf("Expected (42,1), got (%d,%d)", length, skip)
	}

	// Long form: 0x81 0x80 = 128
	length, skip = credCheckBERDecodeLength([]byte{0x81, 0x80})
	if length != 128 || skip != 2 {
		t.Errorf("Expected (128,2), got (%d,%d)", length, skip)
	}

	// Long form: 0x82 0x01 0x00 = 256
	length, skip = credCheckBERDecodeLength([]byte{0x82, 0x01, 0x00})
	if length != 256 || skip != 3 {
		t.Errorf("Expected (256,3), got (%d,%d)", length, skip)
	}
}

func TestCredCheckCancellation(t *testing.T) {
	task := structs.NewTask("cancel-cred", "cred-check", "")
	task.SetStop()

	cmd := &CredCheckCommand{}
	params, _ := json.Marshal(credCheckArgs{
		Hosts:    "127.0.0.1,127.0.0.2",
		Username: "admin",
		Password: "pass",
		Timeout:  1,
	})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}
