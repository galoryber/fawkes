package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestGppPasswordCommandName(t *testing.T) {
	cmd := &GppPasswordCommand{}
	if cmd.Name() != "gpp-password" {
		t.Errorf("expected 'gpp-password', got '%s'", cmd.Name())
	}
}

func TestGppPasswordCommandDescription(t *testing.T) {
	cmd := &GppPasswordCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("description should not be empty")
	}
}

func TestGppPasswordEmptyParams(t *testing.T) {
	cmd := &GppPasswordCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for empty params, got '%s'", result.Status)
	}
}

func TestGppPasswordInvalidJSON(t *testing.T) {
	cmd := &GppPasswordCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got '%s'", result.Status)
	}
}

func TestGppPasswordMissingServer(t *testing.T) {
	cmd := &GppPasswordCommand{}
	params, _ := json.Marshal(map[string]string{
		"username": "user@domain",
		"password": "pass",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing server, got '%s'", result.Status)
	}
}

func TestGppPasswordMissingCredentials(t *testing.T) {
	cmd := &GppPasswordCommand{}
	params, _ := json.Marshal(map[string]string{
		"server": "dc01",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing credentials, got '%s'", result.Status)
	}
}

func TestGppDecryptKnownPassword(t *testing.T) {
	// Known GPP cpassword test vector — this cpassword decrypts to "GPPstillStandingStrong2k18"
	cpassword := "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
	result := gppDecrypt(cpassword)
	if result != "GPPstillStandingStrong2k18" {
		t.Errorf("expected 'GPPstillStandingStrong2k18', got '%s'", result)
	}
}

func TestGppDecryptEmpty(t *testing.T) {
	result := gppDecrypt("")
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestGppUTF16LEToString(t *testing.T) {
	// "AB" in UTF-16LE
	data := []byte{0x41, 0x00, 0x42, 0x00}
	result := gppUTF16LEToString(data)
	if result != "AB" {
		t.Errorf("expected 'AB', got '%s'", result)
	}
}

func TestGppUTF16LEToStringWithNull(t *testing.T) {
	// "A" followed by null terminator
	data := []byte{0x41, 0x00, 0x00, 0x00, 0x42, 0x00}
	result := gppUTF16LEToString(data)
	if result != "A" {
		t.Errorf("expected 'A', got '%s'", result)
	}
}
