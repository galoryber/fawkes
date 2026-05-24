package agentfunctions

import (
	"strings"
	"testing"
)

func TestGetDCOMObjectWarning_MMC20(t *testing.T) {
	w := getDCOMObjectWarning("mmc20")
	if !strings.Contains(w, "MMC20.Application") {
		t.Errorf("expected MMC20 warning, got %q", w)
	}
}

func TestGetDCOMObjectWarning_ShellWindows(t *testing.T) {
	w := getDCOMObjectWarning("shellwindows")
	if !strings.Contains(w, "explorer.exe") {
		t.Errorf("expected explorer.exe reference, got %q", w)
	}
}

func TestGetDCOMObjectWarning_WScript(t *testing.T) {
	w := getDCOMObjectWarning("wscript")
	if !strings.Contains(w, "WScript.Shell") {
		t.Errorf("expected WScript.Shell reference, got %q", w)
	}
}

func TestGetDCOMObjectWarning_Excel(t *testing.T) {
	w := getDCOMObjectWarning("excel")
	if !strings.Contains(w, "Excel") {
		t.Errorf("expected Excel reference, got %q", w)
	}
}

func TestGetDCOMObjectWarning_Outlook(t *testing.T) {
	w := getDCOMObjectWarning("outlook")
	if !strings.Contains(w, "Outlook") {
		t.Errorf("expected Outlook reference, got %q", w)
	}
}

func TestGetDCOMObjectWarning_Unknown(t *testing.T) {
	w := getDCOMObjectWarning("nonexistent")
	if !strings.Contains(w, "Unknown object") {
		t.Errorf("expected 'Unknown object' fallback, got %q", w)
	}
}

func TestExtractDCOMExecutionInfo_Valid(t *testing.T) {
	input := "DCOM MMC20 executed on DC01: success"
	object, host, ok := extractDCOMExecutionInfo(input)
	if !ok {
		t.Fatal("expected match")
	}
	if object != "MMC20" {
		t.Errorf("expected MMC20, got %q", object)
	}
	if host != "DC01" {
		t.Errorf("expected DC01, got %q", host)
	}
}

func TestExtractDCOMExecutionInfo_IPAddress(t *testing.T) {
	input := "DCOM ShellWindows executed on 10.0.0.5: cmd.exe started"
	object, host, ok := extractDCOMExecutionInfo(input)
	if !ok {
		t.Fatal("expected match")
	}
	if object != "ShellWindows" {
		t.Errorf("expected ShellWindows, got %q", object)
	}
	if host != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %q", host)
	}
}

func TestExtractDCOMExecutionInfo_NoMatch(t *testing.T) {
	_, _, ok := extractDCOMExecutionInfo("DCOM connection established to DC01")
	if ok {
		t.Error("expected no match for non-execution output")
	}
}

func TestExtractDCOMExecutionInfo_Empty(t *testing.T) {
	_, _, ok := extractDCOMExecutionInfo("")
	if ok {
		t.Error("expected no match for empty input")
	}
}
