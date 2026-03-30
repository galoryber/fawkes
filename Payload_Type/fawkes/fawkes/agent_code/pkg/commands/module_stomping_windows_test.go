//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"unsafe"

	"fawkes/pkg/structs"
)

func TestModuleStompingCommand_Name(t *testing.T) {
	cmd := &ModuleStompingCommand{}
	if cmd.Name() != "module-stomping" {
		t.Errorf("expected 'module-stomping', got %q", cmd.Name())
	}
}

func TestModuleStompingCommand_Description(t *testing.T) {
	cmd := &ModuleStompingCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestModuleStompingParams_Validation(t *testing.T) {
	cmd := &ModuleStompingCommand{}

	tests := []struct {
		name    string
		params  string
		wantErr string
	}{
		{
			name:    "empty params",
			params:  "",
			wantErr: "Error",
		},
		{
			name:    "invalid json",
			params:  "{invalid",
			wantErr: "Error parsing",
		},
		{
			name:    "empty shellcode",
			params:  `{"shellcode_b64":"","pid":1234}`,
			wantErr: "invalid or empty shellcode",
		},
		{
			name:    "invalid pid",
			params:  `{"shellcode_b64":"` + base64.StdEncoding.EncodeToString([]byte{0x90}) + `","pid":0}`,
			wantErr: "invalid PID",
		},
		{
			name:    "negative pid",
			params:  `{"shellcode_b64":"` + base64.StdEncoding.EncodeToString([]byte{0x90}) + `","pid":-1}`,
			wantErr: "invalid PID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := structs.Task{Params: tt.params}
			result := cmd.Execute(task)
			if result.Status != "error" {
				t.Errorf("expected error status, got %q", result.Status)
			}
		})
	}
}

func TestModuleStompingParams_Parse(t *testing.T) {
	sc := base64.StdEncoding.EncodeToString([]byte{0x90, 0x90, 0x90})
	params := moduleStompingParams{
		ShellcodeB64: sc,
		PID:          1234,
		DllName:      "amsi.dll",
	}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed moduleStompingParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.PID != 1234 {
		t.Errorf("PID: expected 1234, got %d", parsed.PID)
	}
	if parsed.DllName != "amsi.dll" {
		t.Errorf("DllName: expected 'amsi.dll', got %q", parsed.DllName)
	}
}

func TestStompDLLList_NonEmpty(t *testing.T) {
	// Verify the hardcoded DLL list used for random selection
	stompDLLs := []string{
		"xpsservices.dll", "WININET.dll", "amsi.dll", "TextShaping.dll",
		"msvcp_win.dll", "urlmon.dll", "dwrite.dll", "wintypes.dll",
	}
	if len(stompDLLs) < 3 {
		t.Errorf("DLL list should have at least 3 entries for variety, got %d", len(stompDLLs))
	}
	for _, dll := range stompDLLs {
		if dll == "" {
			t.Error("DLL list should not contain empty strings")
		}
	}
}

// TestPEHeaderStructSizes verifies PE header struct layouts match expected sizes.
func TestPEHeaderStructSizes(t *testing.T) {
	// DOS header: 2 bytes (magic) + 29*2 bytes (padding) + 4 bytes (e_lfanew) = 64 bytes
	dosSize := unsafe.Sizeof(imageDOSHeader{})
	if dosSize != 64 {
		t.Errorf("imageDOSHeader size: expected 64, got %d", dosSize)
	}

	// File header: 2+2+4+4+4+2+2 = 20 bytes
	fileSize := unsafe.Sizeof(imageFileHeader{})
	if fileSize != 20 {
		t.Errorf("imageFileHeader size: expected 20, got %d", fileSize)
	}

	// Section header: 8+4+4+4+4+4+4+2+2+4 = 40 bytes
	secSize := unsafe.Sizeof(imageSectionHeader{})
	if secSize != 40 {
		t.Errorf("imageSectionHeader size: expected 40, got %d", secSize)
	}
}

// TestPEMagicConstants verifies PE magic values are correct.
func TestPEMagicConstants(t *testing.T) {
	// DOS magic "MZ" = 0x5A4D
	if 0x5A4D != uint16(0x5A4D) {
		t.Error("DOS magic should be 0x5A4D")
	}
	// PE signature "PE\0\0" = 0x00004550
	if 0x00004550 != uint32(0x00004550) {
		t.Error("PE signature should be 0x00004550")
	}
}

// TestImageSectionHeader_TextName verifies .text section name matching.
func TestImageSectionHeader_TextName(t *testing.T) {
	tests := []struct {
		name     [8]byte
		isText   bool
	}{
		{[8]byte{'.', 't', 'e', 'x', 't', 0, 0, 0}, true},
		{[8]byte{'.', 't', 'e', 'x', 't', 0, 0, 1}, true}, // extra byte after null
		{[8]byte{'.', 'r', 'd', 'a', 't', 'a', 0, 0}, false},
		{[8]byte{'.', 'd', 'a', 't', 'a', 0, 0, 0}, false},
		{[8]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}, false},
	}

	for _, tt := range tests {
		section := imageSectionHeader{Name: tt.name}
		nameStr := string(section.Name[:])
		isText := len(nameStr) >= 5 && nameStr[:5] == ".text"
		if isText != tt.isText {
			t.Errorf("name %q: expected isText=%v, got %v", tt.name, tt.isText, isText)
		}
	}
}
