//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestAvDetect_DeepScanKernelModuleDB(t *testing.T) {
	if len(knownSecurityKernelModules) < 5 {
		t.Errorf("expected 5+ kernel module entries, got %d", len(knownSecurityKernelModules))
	}
	validCategories := map[string]bool{"AV": true, "EDR": true, "Logging": true}
	for mod, product := range knownSecurityKernelModules {
		if !validCategories[product.Category] {
			t.Errorf("kernel module %q has invalid category %q", mod, product.Category)
		}
	}
}

func TestAvDetect_DeepScanSystemdUnitDB(t *testing.T) {
	if len(knownSecuritySystemdUnits) < 10 {
		t.Errorf("expected 10+ systemd unit entries, got %d", len(knownSecuritySystemdUnits))
	}
	for unit, product := range knownSecuritySystemdUnits {
		if !strings.HasSuffix(unit, ".service") {
			t.Errorf("systemd unit %q should end with .service", unit)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("systemd unit %q has empty Product or Vendor", unit)
		}
	}
}

func TestAvDetect_DeepScanConfigPathDB_Linux(t *testing.T) {
	if len(knownSecurityConfigPaths) < 10 {
		t.Errorf("expected 10+ config path entries, got %d", len(knownSecurityConfigPaths))
	}
	for path, product := range knownSecurityConfigPaths {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("config path %q should be absolute", path)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("config path %q has empty Product or Vendor", path)
		}
	}
}
