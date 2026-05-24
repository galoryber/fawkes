//go:build linux

package commands

import (
	"strings"
	"testing"
)

// TestCheckLDPreloadActive covers the `LD_PRELOAD != ""` branch (lines 234-237)
// in checkLDPreload — triggered when the env var is set.
func TestCheckLDPreloadActive(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/fake_inject.so")

	controls := checkLDPreload()
	found := false
	for _, c := range controls {
		if c.Name == "LD_PRELOAD" && c.Status == "warning" {
			found = true
			if !strings.Contains(c.Details, "/tmp/fake_inject.so") {
				t.Errorf("expected LD_PRELOAD path in details, got: %s", c.Details)
			}
		}
	}
	if !found {
		t.Error("expected LD_PRELOAD warning control when env var is set")
	}
}

// TestCheckLDAuditActive covers the `LD_AUDIT != ""` branch (lines 241-244)
// in checkLDPreload — triggered when the LD_AUDIT env var is set.
func TestCheckLDAuditActive(t *testing.T) {
	t.Setenv("LD_PRELOAD", "")  // ensure LD_PRELOAD is not set
	t.Setenv("LD_AUDIT", "/tmp/fake_audit.so")

	controls := checkLDPreload()
	found := false
	for _, c := range controls {
		if c.Name == "LD_AUDIT" && c.Status == "warning" {
			found = true
			if !strings.Contains(c.Details, "/tmp/fake_audit.so") {
				t.Errorf("expected LD_AUDIT path in details, got: %s", c.Details)
			}
		}
	}
	if !found {
		t.Error("expected LD_AUDIT warning control when env var is set")
	}
}
