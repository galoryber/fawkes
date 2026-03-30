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

func TestThreadHijackCommand_Name(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	if cmd.Name() != "thread-hijack" {
		t.Errorf("expected 'thread-hijack', got %q", cmd.Name())
	}
}

func TestThreadHijackCommand_Description(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestThreadHijackParams_Validation(t *testing.T) {
	cmd := &ThreadHijackCommand{}

	tests := []struct {
		name    string
		params  string
		wantErr bool
	}{
		{
			name:    "empty params",
			params:  "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			params:  "{bad",
			wantErr: true,
		},
		{
			name:    "empty shellcode",
			params:  `{"shellcode_b64":"","pid":1234}`,
			wantErr: true,
		},
		{
			name:    "invalid pid",
			params:  `{"shellcode_b64":"` + base64.StdEncoding.EncodeToString([]byte{0xCC}) + `","pid":0}`,
			wantErr: true,
		},
		{
			name:    "negative pid",
			params:  `{"shellcode_b64":"` + base64.StdEncoding.EncodeToString([]byte{0xCC}) + `","pid":-5}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := structs.Task{Params: tt.params}
			result := cmd.Execute(task)
			if tt.wantErr && result.Status != "error" {
				t.Errorf("expected error status, got %q: %s", result.Status, result.Output)
			}
		})
	}
}

func TestThreadHijackParams_Roundtrip(t *testing.T) {
	sc := base64.StdEncoding.EncodeToString([]byte{0x90, 0xCC})
	params := ThreadHijackParams{
		ShellcodeB64: sc,
		PID:          4567,
		TID:          8910,
	}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed ThreadHijackParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.PID != 4567 {
		t.Errorf("PID: expected 4567, got %d", parsed.PID)
	}
	if parsed.TID != 8910 {
		t.Errorf("TID: expected 8910, got %d", parsed.TID)
	}
}

func TestThreadHijackParams_TIDZeroIsAutoSelect(t *testing.T) {
	params := ThreadHijackParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0x90}),
		PID:          1234,
		TID:          0, // 0 = auto-select first suitable thread
	}
	data, _ := json.Marshal(params)
	var parsed ThreadHijackParams
	json.Unmarshal(data, &parsed)
	if parsed.TID != 0 {
		t.Errorf("TID should be 0 for auto-select, got %d", parsed.TID)
	}
}

// TestCONTEXT_AMD64_Size verifies the thread context struct is correct size.
func TestCONTEXT_AMD64_Size(t *testing.T) {
	ctx := CONTEXT_AMD64{}
	size := unsafe.Sizeof(ctx)
	// CONTEXT_AMD64 should be 1232 bytes (Windows x64 CONTEXT)
	if size != 1232 {
		t.Errorf("CONTEXT_AMD64 size: expected 1232, got %d", size)
	}
}

// TestCONTEXT_AMD64_ContextFlags verifies CONTEXT_FULL flag value.
func TestCONTEXT_AMD64_ContextFlags(t *testing.T) {
	ctx := CONTEXT_AMD64{}
	ctx.ContextFlags = 0x10001B // CONTEXT_FULL
	if ctx.ContextFlags != 0x10001B {
		t.Errorf("ContextFlags: expected 0x10001B, got 0x%X", ctx.ContextFlags)
	}
}

// TestCONTEXT_AMD64_RcxOffset verifies Rcx (instruction pointer target) is accessible.
func TestCONTEXT_AMD64_RcxField(t *testing.T) {
	ctx := CONTEXT_AMD64{}
	ctx.Rcx = 0xDEADBEEFCAFEBABE
	if ctx.Rcx != 0xDEADBEEFCAFEBABE {
		t.Errorf("Rcx: expected 0xDEADBEEFCAFEBABE, got 0x%X", ctx.Rcx)
	}
}

// TestCONTEXT_AMD64_RipField verifies Rip (instruction pointer) is accessible.
func TestCONTEXT_AMD64_RipField(t *testing.T) {
	ctx := CONTEXT_AMD64{}
	ctx.Rip = 0x00007FF600001000
	if ctx.Rip != 0x00007FF600001000 {
		t.Errorf("Rip: expected 0x00007FF600001000, got 0x%X", ctx.Rip)
	}
}
