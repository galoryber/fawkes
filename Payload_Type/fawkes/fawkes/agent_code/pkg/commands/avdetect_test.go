package commands

import (
	"encoding/json"
	"strings"
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

func TestAvDetect_AllCategoriesValid(t *testing.T) {
	validCategories := map[string]bool{
		"AV": true, "EDR": true, "Firewall": true,
		"HIPS": true, "DLP": true, "Logging": true,
	}
	for proc, product := range knownSecurityProcesses {
		if !validCategories[product.Category] {
			t.Errorf("process %q has invalid category %q", proc, product.Category)
		}
	}
}

func TestAvDetect_AllEntriesHaveRequiredFields(t *testing.T) {
	for proc, product := range knownSecurityProcesses {
		if product.Product == "" {
			t.Errorf("process %q has empty Product", proc)
		}
		if product.Vendor == "" {
			t.Errorf("process %q has empty Vendor", proc)
		}
		if product.Category == "" {
			t.Errorf("process %q has empty Category", proc)
		}
	}
}

func TestAvDetect_AllKeysAreLowercase(t *testing.T) {
	for proc := range knownSecurityProcesses {
		if proc != strings.ToLower(proc) {
			t.Errorf("process key %q should be lowercase (got mixed case)", proc)
		}
	}
}

func TestAvDetect_VendorCoverage(t *testing.T) {
	// Verify major EDR/AV vendors are represented
	requiredVendors := []string{
		"Microsoft", "CrowdStrike", "SentinelOne", "VMware",
		"Palo Alto", "Broadcom", "Trellix", "Kaspersky",
		"ESET", "Sophos", "Trend Micro", "Bitdefender",
		"Elastic", "Cisco", "Splunk",
	}
	vendorFound := make(map[string]bool)
	for _, product := range knownSecurityProcesses {
		vendorFound[product.Vendor] = true
	}
	for _, vendor := range requiredVendors {
		if !vendorFound[vendor] {
			t.Errorf("missing required vendor %q in security process database", vendor)
		}
	}
}

func TestAvDetect_PlatformCoverage(t *testing.T) {
	// Verify Linux, macOS, and Windows processes exist
	var hasWindows, hasLinux, hasMacOS bool
	for proc := range knownSecurityProcesses {
		if strings.HasSuffix(proc, ".exe") {
			hasWindows = true
		}
		switch proc {
		case "clamd", "freshclam", "auditd", "falcond", "falcon-sensor",
			"sentinelagent", "cbdefense", "esets_daemon", "elastic-agent",
			"elastic-endpoint", "taniumclient", "sysmon", "splunkd",
			"wazuh-agentd", "ossec-agentd":
			hasLinux = true
		case "xprotectservice", "endpointsecurityd":
			hasMacOS = true
		}
	}
	if !hasWindows {
		t.Error("no Windows processes (.exe) found in database")
	}
	if !hasLinux {
		t.Error("no Linux processes found in database")
	}
	if !hasMacOS {
		t.Error("no macOS processes found in database")
	}
}

func TestAvDetect_CategoryDistribution(t *testing.T) {
	// Verify we have a reasonable spread across categories
	categoryCount := make(map[string]int)
	for _, product := range knownSecurityProcesses {
		categoryCount[product.Category]++
	}

	// AV and EDR should dominate
	if categoryCount["AV"] < 10 {
		t.Errorf("expected 10+ AV entries, got %d", categoryCount["AV"])
	}
	if categoryCount["EDR"] < 10 {
		t.Errorf("expected 10+ EDR entries, got %d", categoryCount["EDR"])
	}
	if categoryCount["Logging"] < 3 {
		t.Errorf("expected 3+ Logging entries, got %d", categoryCount["Logging"])
	}
}

func TestAvDetect_OutputIsJSON(t *testing.T) {
	cmd := &AvDetectCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Skipf("skipping JSON test: %s", result.Output)
	}

	// Output should be valid JSON (either [] or [...])
	var parsed interface{}
	if err := json.Unmarshal([]byte(result.Output), &parsed); err != nil {
		t.Errorf("output is not valid JSON: %v (output: %q)", err, result.Output)
	}
}

func TestAvDetect_OutputStructure(t *testing.T) {
	cmd := &AvDetectCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Skipf("skipping structure test: %s", result.Output)
	}

	// Parse into detected products
	var detected []detectedProduct
	if err := json.Unmarshal([]byte(result.Output), &detected); err != nil {
		t.Fatalf("failed to parse output as []detectedProduct: %v", err)
	}

	// Every detected product must have all fields
	for i, d := range detected {
		if d.Product == "" {
			t.Errorf("detected[%d] has empty Product", i)
		}
		if d.Vendor == "" {
			t.Errorf("detected[%d] has empty Vendor", i)
		}
		if d.Category == "" {
			t.Errorf("detected[%d] has empty Category", i)
		}
		if d.ProcessName == "" {
			t.Errorf("detected[%d] has empty ProcessName", i)
		}
		if d.PID <= 0 {
			t.Errorf("detected[%d] has invalid PID %d", i, d.PID)
		}
	}
}

func TestAvDetect_NoDetectionReturnsEmptyArray(t *testing.T) {
	// On a CI system without AV, output should be "[]"
	cmd := &AvDetectCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Skipf("execution failed: %s", result.Output)
	}

	// If no products detected, output must be exactly "[]"
	var detected []detectedProduct
	if err := json.Unmarshal([]byte(result.Output), &detected); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(detected) == 0 && result.Output != "[]" {
		t.Errorf("expected '[]' for empty detection, got %q", result.Output)
	}
}

func TestAvDetect_DeepScanParameter(t *testing.T) {
	cmd := &AvDetectCommand{}
	// Deep scan should succeed even on clean systems
	params, _ := json.Marshal(avDetectArgs{Deep: true})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("deep scan failed: %s", result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Output should be valid JSON
	var detected []detectedProduct
	if err := json.Unmarshal([]byte(result.Output), &detected); err != nil {
		t.Errorf("deep scan output not valid JSON: %v", err)
	}
}

func TestAvDetect_DeepScanDeduplication(t *testing.T) {
	// Run deep scan and verify no duplicate vendor:product pairs
	results := avDeepScan()
	seen := make(map[string]bool)
	for _, r := range results {
		key := r.Vendor + ":" + r.Product
		if seen[key] {
			t.Errorf("duplicate detection: %s (process=%s)", key, r.ProcessName)
		}
		seen[key] = true
	}
}

func TestAvDetect_DeepScanFieldsValid(t *testing.T) {
	results := avDeepScan()
	// Valid source prefixes across all platforms
	validPrefixes := []string{
		"kmod:", "systemd:", "config:",       // Linux
		"kext:", "sysext:", "launchdaemon:",  // macOS
		"launchagent:", "app:",               // macOS
	}
	for _, r := range results {
		if r.Product == "" {
			t.Errorf("empty Product for %s", r.ProcessName)
		}
		if r.Vendor == "" {
			t.Errorf("empty Vendor for %s", r.ProcessName)
		}
		if r.Category == "" {
			t.Errorf("empty Category for %s", r.ProcessName)
		}
		if r.ProcessName == "" {
			t.Error("empty ProcessName in deep scan result")
		}
		// Deep scan results should have PID 0
		if r.PID != 0 {
			t.Errorf("deep scan PID should be 0, got %d for %s", r.PID, r.ProcessName)
		}
		// ProcessName should have a known source prefix
		hasPrefix := false
		for _, prefix := range validPrefixes {
			if strings.HasPrefix(r.ProcessName, prefix) {
				hasPrefix = true
				break
			}
		}
		if !hasPrefix {
			t.Errorf("deep scan ProcessName %q should have a known source prefix", r.ProcessName)
		}
	}
}

func TestAvDetect_NoDuplicateProducts(t *testing.T) {
	// Different process names can map to the same product, but
	// within the same vendor+product, the category must be consistent
	type key struct{ vendor, product string }
	seen := make(map[key]string)
	for proc, sp := range knownSecurityProcesses {
		k := key{sp.Vendor, sp.Product}
		if prevCat, ok := seen[k]; ok {
			if prevCat != sp.Category {
				t.Errorf("inconsistent category for %s/%s: process %q has %q but others have %q",
					sp.Vendor, sp.Product, proc, sp.Category, prevCat)
			}
		}
		seen[k] = sp.Category
	}
}
