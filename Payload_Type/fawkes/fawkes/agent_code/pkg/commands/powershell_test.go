//go:build windows

package commands

import (
	"testing"
)

func TestPowershellCommandName(t *testing.T) {
	assertCommandName(t, &PowershellCommand{}, "powershell")
}

func TestPowershellCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &PowershellCommand{})
}

func TestPowershellEmptyParams(t *testing.T) {
	cmd := &PowershellCommand{}
	result := cmd.Execute(mockTask("powershell", ""))
	assertError(t, result)
	assertOutputContains(t, result, "No command specified")
}

func TestParsePowershellParamsJSON(t *testing.T) {
	cmd, encoded := parsePowershellParams(`{"command":"Get-Process","encoded":false}`)
	if cmd != "Get-Process" {
		t.Errorf("command = %q, want Get-Process", cmd)
	}
	if encoded {
		t.Error("encoded should be false")
	}
}

func TestParsePowershellParamsJSONEncoded(t *testing.T) {
	cmd, encoded := parsePowershellParams(`{"command":"R2V0LVByb2Nlc3M=","encoded":true}`)
	if cmd != "R2V0LVByb2Nlc3M=" {
		t.Errorf("command = %q, want R2V0LVByb2Nlc3M=", cmd)
	}
	if !encoded {
		t.Error("encoded should be true")
	}
}

func TestParsePowershellParamsPlainText(t *testing.T) {
	cmd, encoded := parsePowershellParams("Get-Process | Select-Object Name")
	if cmd != "Get-Process | Select-Object Name" {
		t.Errorf("command = %q, want full command", cmd)
	}
	if encoded {
		t.Error("encoded should be false for plain text")
	}
}

func TestParsePowershellParamsEmpty(t *testing.T) {
	cmd, encoded := parsePowershellParams("")
	if cmd != "" {
		t.Errorf("command should be empty, got %q", cmd)
	}
	if encoded {
		t.Error("encoded should be false for empty")
	}
}
