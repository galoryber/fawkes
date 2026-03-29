//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPoolPartyInjection_Name(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	if got := cmd.Name(); got != "poolparty-injection" {
		t.Errorf("Name() = %q, want %q", got, "poolparty-injection")
	}
}

func TestPoolPartyInjection_Description(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPoolPartyInjection_InvalidJSON(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_MissingShellcode(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	params, _ := json.Marshal(PoolPartyInjectionParams{
		PID:     1234,
		Variant: 2,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_InvalidPID(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	params, _ := json.Marshal(PoolPartyInjectionParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0xCC}),
		PID:          0,
		Variant:      2,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid PID should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_NegativePID(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	params, _ := json.Marshal(PoolPartyInjectionParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0xCC}),
		PID:          -1,
		Variant:      2,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Negative PID should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_InvalidBase64(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	params, _ := json.Marshal(PoolPartyInjectionParams{
		ShellcodeB64: "not-valid-base64!!!",
		PID:          1234,
		Variant:      2,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_EmptyShellcodeAfterDecode(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	params, _ := json.Marshal(PoolPartyInjectionParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{}),
		PID:          1234,
		Variant:      2,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_UnsupportedVariant(t *testing.T) {
	cmd := &PoolPartyInjectionCommand{}
	params, _ := json.Marshal(PoolPartyInjectionParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0xCC}),
		PID:          1234,
		Variant:      99,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unsupported variant should error, got status=%q", result.Status)
	}
}

func TestPoolPartyInjection_ParamParsing(t *testing.T) {
	input := `{"shellcode_b64":"AQID","pid":9999,"variant":3}`
	var params PoolPartyInjectionParams
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if params.PID != 9999 {
		t.Errorf("PID = %d, want 9999", params.PID)
	}
	if params.Variant != 3 {
		t.Errorf("Variant = %d, want 3", params.Variant)
	}
	decoded, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) != 3 {
		t.Errorf("Decoded len = %d, want 3", len(decoded))
	}
}

func TestPoolPartyInjection_AllValidVariants(t *testing.T) {
	// Verify variants 1-8 are recognized (they'll fail at runtime but not at validation)
	for v := 1; v <= 8; v++ {
		params, _ := json.Marshal(PoolPartyInjectionParams{
			ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0xCC}),
			PID:          1234,
			Variant:      v,
		})
		result := (&PoolPartyInjectionCommand{}).Execute(structs.Task{Params: string(params)})
		// These will fail at the actual injection (no real process), but should NOT fail
		// at parameter validation — so status should be "error" (injection fails) not
		// "unsupported variant"
		if result.Status == "success" {
			// Shouldn't succeed without a real process, but if it does that's fine
			continue
		}
		// Verify it's NOT an "Unsupported variant" error
		if result.Output != "" {
			for _, line := range []string{"Unsupported variant"} {
				if strings.Contains(result.Output, line) {
					t.Errorf("Variant %d should be supported, got: %s", v, result.Output)
				}
			}
		}
	}
}

