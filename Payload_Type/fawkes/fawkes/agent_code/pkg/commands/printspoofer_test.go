//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestPrintSpooferCommandName(t *testing.T) {
	assertCommandName(t, &PrintSpooferCommand{}, "printspoofer")
}

func TestPrintSpooferCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &PrintSpooferCommand{})
}

func TestPrintSpooferEmptyParams(t *testing.T) {
	cmd := &PrintSpooferCommand{}
	// Empty params should not panic — command checks privileges first
	result := cmd.Execute(mockTask("printspoofer", ""))
	// Will likely fail on privilege check in test env
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestPrintSpooferArgsUnmarshal(t *testing.T) {
	var args printSpooferArgs
	data := `{"timeout":120}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Timeout != 120 {
		t.Errorf("expected timeout=120, got %d", args.Timeout)
	}
}

func TestPrintSpooferDefaultTimeout(t *testing.T) {
	var args printSpooferArgs
	data := `{}`
	json.Unmarshal([]byte(data), &args)
	// Default is applied in Execute, not in struct
	if args.Timeout != 0 {
		t.Errorf("expected zero-value timeout before defaults, got %d", args.Timeout)
	}
}
