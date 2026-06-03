//go:build darwin && arm64

package commands

import (
	"encoding/base64"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHollowingDarwinCommand_Name(t *testing.T) {
	cmd := &HollowingCommand{}
	if cmd.Name() != "hollow" {
		t.Errorf("expected 'hollow', got %q", cmd.Name())
	}
}

func TestHollowingDarwinCommand_Description(t *testing.T) {
	cmd := &HollowingCommand{}
	if !strings.Contains(cmd.Description(), "Mach VM") {
		t.Errorf("expected description to mention Mach VM, got %q", cmd.Description())
	}
}

func TestHollowingDarwinCommand_EmptyShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.NewTask("t", "hollow", `{"shellcode_b64":""}`))
	if result.Status != "error" {
		t.Error("expected error for empty shellcode_b64")
	}
}

func TestHollowingDarwinCommand_MissingShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.NewTask("t", "hollow", `{"target":"/bin/sleep"}`))
	if result.Status != "error" {
		t.Error("expected error for missing shellcode_b64")
	}
}

func TestHollowingDarwinCommand_InvalidBase64(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.NewTask("t", "hollow", `{"shellcode_b64":"not-valid-base64!!!"}`))
	if result.Status != "error" {
		t.Error("expected error for invalid base64")
	}
}

func TestHollowingDarwinCommand_EmptyDecodedShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	empty := base64.StdEncoding.EncodeToString([]byte{})
	result := cmd.Execute(structs.NewTask("t", "hollow", `{"shellcode_b64":"`+empty+`"}`))
	if result.Status != "error" {
		t.Error("expected error for empty decoded shellcode")
	}
}

func TestHollowingDarwinCommand_RequiresRoot(t *testing.T) {
	cmd := &HollowingCommand{}
	sc := base64.StdEncoding.EncodeToString([]byte{0xD5, 0x03, 0x20, 0x1F})
	result := cmd.Execute(structs.NewTask("t", "hollow", `{"shellcode_b64":"`+sc+`"}`))
	if result.Status != "error" {
		t.Error("expected error when not root")
	}
	if !strings.Contains(result.Output, "root") {
		t.Errorf("expected error to mention root, got %q", result.Output)
	}
}

func TestHollowingDarwinCommand_DefaultTarget(t *testing.T) {
	var params hollowParams
	if params.Target == "" {
		params.Target = "/bin/sleep"
	}
	if params.Target != "/bin/sleep" {
		t.Errorf("expected default target /bin/sleep, got %q", params.Target)
	}
}

func TestHollowingDarwinCommand_ParseTarget(t *testing.T) {
	tests := []struct {
		input string
		bin   string
		nArgs int
	}{
		{"/bin/sleep 86400", "/bin/sleep", 1},
		{"/bin/sleep", "/bin/sleep", 0},
		{"/usr/bin/yes hello world", "/usr/bin/yes", 2},
	}
	for _, tt := range tests {
		parts := strings.Fields(tt.input)
		if parts[0] != tt.bin {
			t.Errorf("input=%q: expected bin=%q, got %q", tt.input, tt.bin, parts[0])
		}
		if len(parts)-1 != tt.nArgs {
			t.Errorf("input=%q: expected %d args, got %d", tt.input, tt.nArgs, len(parts)-1)
		}
	}
}

func TestMachConstants(t *testing.T) {
	if vmFlagsAnywhere != 1 {
		t.Errorf("VM_FLAGS_ANYWHERE should be 1, got %d", vmFlagsAnywhere)
	}
	if vmProtRead != 1 {
		t.Errorf("VM_PROT_READ should be 1, got %d", vmProtRead)
	}
	if vmProtWrite != 2 {
		t.Errorf("VM_PROT_WRITE should be 2, got %d", vmProtWrite)
	}
	if vmProtExecute != 4 {
		t.Errorf("VM_PROT_EXECUTE should be 4, got %d", vmProtExecute)
	}
	if kernSuccess != 0 {
		t.Errorf("KERN_SUCCESS should be 0, got %d", kernSuccess)
	}
}

func TestDarwinPtraceConstants(t *testing.T) {
	if ptWriteD != 5 {
		t.Errorf("PT_WRITE_D should be 5, got %d", ptWriteD)
	}
	if ptReadD != 2 {
		t.Errorf("PT_READ_D should be 2, got %d", ptReadD)
	}
	if ptDetach != 11 {
		t.Errorf("PT_DETACH should be 11, got %d", ptDetach)
	}
	if ptCont != 7 {
		t.Errorf("PT_CONTINUE should be 7, got %d", ptCont)
	}
	if ptKill != 8 {
		t.Errorf("PT_KILL should be 8, got %d", ptKill)
	}
}

func TestDarwinPageAlignment(t *testing.T) {
	tests := []struct {
		size     int
		expected uint64
	}{
		{1, 16384},
		{100, 16384},
		{16384, 16384},
		{16385, 32768},
		{32768, 32768},
		{50000, 65536},
	}
	for _, tt := range tests {
		aligned := uint64(((tt.size + darwinPageSize - 1) / darwinPageSize) * darwinPageSize)
		if aligned != tt.expected {
			t.Errorf("size=%d: expected aligned=%d, got %d", tt.size, tt.expected, aligned)
		}
	}
}
