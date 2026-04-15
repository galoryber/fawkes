//go:build linux && amd64

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHollowingLinux_Name(t *testing.T) {
	cmd := &HollowingCommand{}
	if got := cmd.Name(); got != "hollow" {
		t.Errorf("Name() = %q, want %q", got, "hollow")
	}
}

func TestHollowingLinux_Description(t *testing.T) {
	cmd := &HollowingCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "hollowing") {
		t.Errorf("Description should mention hollowing, got %q", desc)
	}
}

func TestHollowingLinux_EmptyShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":""}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestHollowingLinux_NoShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestHollowingLinux_InvalidBase64(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"not-valid-base64!!!"}`})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestHollowingLinux_InvalidJSON(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestHollowingLinux_DefaultTarget(t *testing.T) {
	var p hollowParams
	_ = json.Unmarshal([]byte(`{"shellcode_b64":"AQID"}`), &p)
	if p.Target != "" {
		t.Errorf("Default target should be empty (set at execution), got %q", p.Target)
	}
}

func TestHollowingLinux_CustomTarget(t *testing.T) {
	var p hollowParams
	_ = json.Unmarshal([]byte(`{"shellcode_b64":"AQID","target":"/usr/bin/cat"}`), &p)
	if p.Target != "/usr/bin/cat" {
		t.Errorf("Target = %q, want /usr/bin/cat", p.Target)
	}
}

func TestHollowingLinux_InvalidTarget(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","target":"/nonexistent/binary"}`})
	if result.Status != "error" {
		t.Errorf("Nonexistent target should error, got status=%q", result.Status)
	}
}

func TestHollowingLinux_ParamsParsing(t *testing.T) {
	var p hollowParams
	input := `{"shellcode_b64":"AQID","target":"/bin/sh","ppid":1234,"block_dlls":true}`
	if err := json.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if p.ShellcodeB64 != "AQID" {
		t.Errorf("ShellcodeB64 = %q, want AQID", p.ShellcodeB64)
	}
	if p.Target != "/bin/sh" {
		t.Errorf("Target = %q, want /bin/sh", p.Target)
	}
	if p.Ppid != 1234 {
		t.Errorf("Ppid = %d, want 1234", p.Ppid)
	}
	if !p.BlockDLLs {
		t.Error("BlockDLLs should be true")
	}
}
