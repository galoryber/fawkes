package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

func TestAvDetectName(t *testing.T) {
	cmd := &AvDetectCommand{}
	if cmd.Name() != "av-detect" {
		t.Errorf("expected 'av-detect', got '%s'", cmd.Name())
	}
}

func TestAvDetectDescription(t *testing.T) {
	cmd := &AvDetectCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestAvDetectDefault(t *testing.T) {
	cmd := &AvDetectCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed to be true")
	}
}

func TestAvDetectKnownProcesses(t *testing.T) {
	// Verify the known security processes map is populated
	if len(knownSecurityProcesses) < 50 {
		t.Errorf("expected 50+ known security processes, got %d", len(knownSecurityProcesses))
	}
	// Spot-check a few well-known entries
	checks := map[string]string{
		"msmpeng.exe":         "Windows Defender",
		"csfalconservice.exe": "CrowdStrike Falcon",
		"sentinelagent.exe":   "SentinelOne",
		"cb.exe":              "Carbon Black",
	}
	for proc, expectedProduct := range checks {
		product, ok := knownSecurityProcesses[proc]
		if !ok {
			t.Errorf("expected '%s' in known processes", proc)
			continue
		}
		if product.Product != expectedProduct {
			t.Errorf("expected product '%s' for '%s', got '%s'", expectedProduct, proc, product.Product)
		}
	}
}
