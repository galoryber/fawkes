//go:build darwin

package commands

import (
	"testing"
)

func TestClassifyDarwinHWModel_VMware(t *testing.T) {
	indicators := classifyDarwinHWModel("VMware7,1")
	if len(indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(indicators))
	}
	if indicators[0] == "" {
		t.Error("expected non-empty indicator string")
	}
}

func TestClassifyDarwinHWModel_Parallels(t *testing.T) {
	indicators := classifyDarwinHWModel("Parallels Virtual Platform")
	if len(indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(indicators))
	}
}

func TestClassifyDarwinHWModel_QEMU(t *testing.T) {
	indicators := classifyDarwinHWModel("QEMU Virtual Machine")
	if len(indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(indicators))
	}
}

func TestClassifyDarwinHWModel_VirtualBox(t *testing.T) {
	indicators := classifyDarwinHWModel("VirtualBox")
	if len(indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(indicators))
	}
}

func TestClassifyDarwinHWModel_RealHardware(t *testing.T) {
	// Real Mac hardware models should return no indicators
	realModels := []string{
		"MacBookPro18,1",
		"Mac14,2",
		"MacPro7,1",
		"iMac21,1",
		"Macmini9,1",
	}

	for _, model := range realModels {
		indicators := classifyDarwinHWModel(model)
		if len(indicators) != 0 {
			t.Errorf("classifyDarwinHWModel(%q) returned %d indicators, expected 0", model, len(indicators))
		}
	}
}

func TestClassifyDarwinHWModel_CaseInsensitive(t *testing.T) {
	indicators := classifyDarwinHWModel("VMWARE7,1")
	if len(indicators) != 1 {
		t.Errorf("expected case-insensitive match for VMWARE, got %d indicators", len(indicators))
	}
}

func TestClassifyDarwinHWModel_Empty(t *testing.T) {
	indicators := classifyDarwinHWModel("")
	if len(indicators) != 0 {
		t.Errorf("expected 0 indicators for empty model, got %d", len(indicators))
	}
}

func TestCheckAnalysisEnvironment_Clean(t *testing.T) {
	// In a normal test environment, analysis env vars should not be set
	check := checkAnalysisEnvironment()
	// Just verify it returns a valid check (don't assert CLEAN since CI may differ)
	if check.Name == "" {
		t.Error("expected non-empty check name")
	}
	if check.Status != "CLEAN" && check.Status != "WARNING" {
		t.Errorf("expected CLEAN or WARNING status, got %q", check.Status)
	}
}

func TestCheckSecurityProducts_Valid(t *testing.T) {
	// Verify the check returns a valid result
	check := checkSecurityProducts()
	if check.Name == "" {
		t.Error("expected non-empty check name")
	}
	if check.Status != "CLEAN" && check.Status != "WARNING" {
		t.Errorf("expected CLEAN or WARNING status, got %q", check.Status)
	}
}

func TestCheckVMIndicators_Valid(t *testing.T) {
	check := checkVMIndicators()
	if check.Name == "" {
		t.Error("expected non-empty check name")
	}
	if check.Status != "CLEAN" && check.Status != "WARNING" {
		t.Errorf("expected CLEAN or WARNING status, got %q", check.Status)
	}
}
