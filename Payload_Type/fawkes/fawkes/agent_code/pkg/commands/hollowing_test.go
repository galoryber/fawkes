//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestHollowing_Name(t *testing.T) {
	cmd := &HollowingCommand{}
	if got := cmd.Name(); got != "hollow" {
		t.Errorf("Name() = %q, want %q", got, "hollow")
	}
}

func TestHollowing_Description(t *testing.T) {
	cmd := &HollowingCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestHollowing_EmptyParams(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("Empty params should error, got status=%q", result.Status)
	}
}

func TestHollowing_InvalidJSON(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestHollowing_MissingShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	params, _ := json.Marshal(hollowParams{
		Target: `C:\Windows\System32\svchost.exe`,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestHollowing_InvalidBase64(t *testing.T) {
	cmd := &HollowingCommand{}
	params, _ := json.Marshal(hollowParams{
		ShellcodeB64: "not-valid!!!",
		Target:       `C:\Windows\System32\svchost.exe`,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestHollowing_EmptyShellcodeAfterDecode(t *testing.T) {
	cmd := &HollowingCommand{}
	params, _ := json.Marshal(hollowParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{}),
		Target:       `C:\Windows\System32\svchost.exe`,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestHollowing_ParamParsing(t *testing.T) {
	input := `{"shellcode_b64":"AQID","target":"C:\\Windows\\notepad.exe","ppid":4444,"block_dlls":true}`
	var params hollowParams
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if params.ShellcodeB64 != "AQID" {
		t.Errorf("ShellcodeB64 = %q, want %q", params.ShellcodeB64, "AQID")
	}
	if params.Target != `C:\Windows\notepad.exe` {
		t.Errorf("Target = %q, want %q", params.Target, `C:\Windows\notepad.exe`)
	}
	if params.Ppid != 4444 {
		t.Errorf("Ppid = %d, want 4444", params.Ppid)
	}
	if !params.BlockDLLs {
		t.Error("BlockDLLs should be true")
	}
}

func TestHollowing_DefaultTarget(t *testing.T) {
	// When target is empty, the command should default to svchost.exe
	input := `{"shellcode_b64":"AQID"}`
	var params hollowParams
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if params.Target != "" {
		t.Errorf("Target should be empty from JSON (default set at runtime), got %q", params.Target)
	}
}
