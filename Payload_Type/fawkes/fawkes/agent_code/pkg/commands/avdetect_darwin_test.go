//go:build darwin

package commands

import (
	"strings"
	"testing"
)

func TestAvDetect_DarwinKextDB(t *testing.T) {
	if len(knownSecurityKexts) < 5 {
		t.Errorf("expected 5+ kext entries, got %d", len(knownSecurityKexts))
	}
	validCategories := map[string]bool{"AV": true, "EDR": true, "Firewall": true}
	for kext, product := range knownSecurityKexts {
		if kext != strings.ToLower(kext) {
			t.Errorf("kext key %q should be lowercase", kext)
		}
		if !validCategories[product.Category] {
			t.Errorf("kext %q has unexpected category %q", kext, product.Category)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("kext %q has empty Product or Vendor", kext)
		}
	}
}

func TestAvDetect_DarwinSystemExtensionDB(t *testing.T) {
	if len(knownSecuritySystemExtensions) < 5 {
		t.Errorf("expected 5+ system extension entries, got %d", len(knownSecuritySystemExtensions))
	}
	for ext, product := range knownSecuritySystemExtensions {
		if !strings.HasPrefix(ext, "com.") && !strings.HasPrefix(ext, "at.") {
			t.Errorf("system extension %q should have reverse-domain prefix", ext)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("system extension %q has empty Product or Vendor", ext)
		}
	}
}

func TestAvDetect_DarwinLaunchDaemonDB(t *testing.T) {
	if len(knownSecurityLaunchDaemons) < 15 {
		t.Errorf("expected 15+ LaunchDaemon entries, got %d", len(knownSecurityLaunchDaemons))
	}
	for daemon, product := range knownSecurityLaunchDaemons {
		if !strings.HasSuffix(daemon, ".plist") {
			t.Errorf("LaunchDaemon %q should end with .plist", daemon)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("LaunchDaemon %q has empty Product or Vendor", daemon)
		}
	}
}

func TestAvDetect_DarwinAppDB(t *testing.T) {
	if len(knownSecurityApps) < 15 {
		t.Errorf("expected 15+ application entries, got %d", len(knownSecurityApps))
	}
	for app, product := range knownSecurityApps {
		if !strings.HasSuffix(app, ".app") {
			t.Errorf("application %q should end with .app", app)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("application %q has empty Product or Vendor", app)
		}
	}
}

func TestAvDetect_DarwinConfigDirDB(t *testing.T) {
	if len(knownSecurityConfigDirs) < 15 {
		t.Errorf("expected 15+ config dir entries, got %d", len(knownSecurityConfigDirs))
	}
	for path, product := range knownSecurityConfigDirs {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("config path %q should be absolute", path)
		}
		if product.Product == "" || product.Vendor == "" {
			t.Errorf("config path %q has empty Product or Vendor", path)
		}
	}
}

func TestAvDetect_DarwinVendorCoverage(t *testing.T) {
	// Verify major macOS security vendors are represented across all DB maps
	requiredVendors := []string{
		"CrowdStrike", "SentinelOne", "VMware", "Microsoft",
		"Sophos", "ESET", "Elastic", "Palo Alto",
		"Jamf", "Cisco", "Malwarebytes",
	}

	vendorFound := make(map[string]bool)
	for _, product := range knownSecurityLaunchDaemons {
		vendorFound[product.Vendor] = true
	}
	for _, product := range knownSecurityApps {
		vendorFound[product.Vendor] = true
	}
	for _, product := range knownSecurityConfigDirs {
		vendorFound[product.Vendor] = true
	}

	for _, vendor := range requiredVendors {
		if !vendorFound[vendor] {
			t.Errorf("missing required vendor %q in macOS deep scan databases", vendor)
		}
	}
}

func TestAvDetect_DarwinCategoryConsistency(t *testing.T) {
	validCategories := map[string]bool{
		"AV": true, "EDR": true, "Firewall": true,
		"HIPS": true, "DLP": true, "Logging": true,
	}

	checkMap := func(name string, m map[string]securityProduct) {
		for key, product := range m {
			if !validCategories[product.Category] {
				t.Errorf("%s entry %q has invalid category %q", name, key, product.Category)
			}
		}
	}

	checkMap("kexts", knownSecurityKexts)
	checkMap("system extensions", knownSecuritySystemExtensions)
	checkMap("LaunchDaemons", knownSecurityLaunchDaemons)
	checkMap("apps", knownSecurityApps)
	checkMap("config dirs", knownSecurityConfigDirs)
}
