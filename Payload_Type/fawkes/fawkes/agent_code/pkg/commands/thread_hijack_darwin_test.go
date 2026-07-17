//go:build darwin

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestThreadHijackDarwin_Name(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	if cmd.Name() != "thread-hijack" {
		t.Errorf("expected 'thread-hijack', got %q", cmd.Name())
	}
}

func TestThreadHijackDarwin_Description(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestThreadHijackDarwin_EmptyShellcode(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: `{"shellcode_b64":"","pid":1234}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty shellcode, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_InvalidPID(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	sc := base64.StdEncoding.EncodeToString([]byte{0xCC})
	task := structs.Task{Params: `{"shellcode_b64":"` + sc + `","pid":0}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for PID 0, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_NegativePID(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	sc := base64.StdEncoding.EncodeToString([]byte{0xCC})
	task := structs.Task{Params: `{"shellcode_b64":"` + sc + `","pid":-5}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for negative PID, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_InvalidBase64(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: `{"shellcode_b64":"not-valid-base64!!!","pid":1234}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid base64, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_InvalidJSON(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: `{bad json`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_EmptyParams(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: ``}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
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

func TestThreadHijackParams_TIDZeroAutoSelect(t *testing.T) {
	params := ThreadHijackParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0x90}),
		PID:          1234,
		TID:          0,
	}
	data, _ := json.Marshal(params)
	var parsed ThreadHijackParams
	json.Unmarshal(data, &parsed)
	if parsed.TID != 0 {
		t.Errorf("TID should be 0 for auto-select, got %d", parsed.TID)
	}
}

