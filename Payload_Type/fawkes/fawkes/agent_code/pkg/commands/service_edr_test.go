package commands

import (
	"strings"
	"testing"
)

func TestEdrKnownServicesNotEmpty(t *testing.T) {
	if len(edrKnownServices) == 0 {
		t.Error("edrKnownServices should not be empty")
	}
}

func TestEdrMatchesForPlatform(t *testing.T) {
	tests := []struct {
		platform string
		minCount int
	}{
		{"windows", 20},
		{"linux", 5},
		{"darwin", 1},
	}

	for _, tt := range tests {
		matches := edrMatchesForPlatform(tt.platform)
		if len(matches) < tt.minCount {
			t.Errorf("platform %s: expected at least %d matches, got %d", tt.platform, tt.minCount, len(matches))
		}
		// Verify all returned entries match the platform
		for _, m := range matches {
			if m.Platform != tt.platform && m.Platform != "all" {
				t.Errorf("platform %s: got entry with platform %q (service: %s)", tt.platform, m.Platform, m.ServiceName)
			}
		}
	}
}

func TestEdrMatchesForPlatformIncludesAll(t *testing.T) {
	// "all" platform entries should appear in every platform query
	allEntries := edrMatchesForPlatform("all")
	// While there's no literal "all" match query, "all" entries appear in each platform
	for _, platform := range []string{"windows", "linux", "darwin"} {
		matches := edrMatchesForPlatform(platform)
		for _, allEntry := range edrKnownServices {
			if allEntry.Platform != "all" {
				continue
			}
			found := false
			for _, m := range matches {
				if m.ServiceName == allEntry.ServiceName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("'all' entry %s missing from platform %s results", allEntry.ServiceName, platform)
			}
		}
	}
	_ = allEntries
}

func TestEdrEntriesHaveRequiredFields(t *testing.T) {
	for i, entry := range edrKnownServices {
		if entry.ServiceName == "" {
			t.Errorf("entry %d: ServiceName is empty", i)
		}
		if entry.Vendor == "" {
			t.Errorf("entry %d (%s): Vendor is empty", i, entry.ServiceName)
		}
		if entry.Product == "" {
			t.Errorf("entry %d (%s): Product is empty", i, entry.ServiceName)
		}
		if entry.Platform == "" {
			t.Errorf("entry %d (%s): Platform is empty", i, entry.ServiceName)
		}
		validPlatforms := map[string]bool{"windows": true, "linux": true, "darwin": true, "all": true}
		if !validPlatforms[entry.Platform] {
			t.Errorf("entry %d (%s): invalid platform %q", i, entry.ServiceName, entry.Platform)
		}
	}
}

func TestEdrEntriesUniqueServiceNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, entry := range edrKnownServices {
		if seen[entry.ServiceName] {
			t.Errorf("duplicate service name: %s", entry.ServiceName)
		}
		seen[entry.ServiceName] = true
	}
}

func TestFormatEdrEnumResultsEmpty(t *testing.T) {
	result := formatEdrEnumResults(nil)
	if !strings.Contains(result, "No EDR/AV") {
		t.Errorf("empty results should say 'No EDR/AV', got: %s", result)
	}
}

func TestFormatEdrEnumResultsWithData(t *testing.T) {
	results := []edrEnumResult{
		{ServiceName: "WinDefend", Vendor: "Microsoft", Product: "Defender", Status: "running"},
		{ServiceName: "CSFalconService", Vendor: "CrowdStrike", Product: "Falcon", Status: "stopped"},
	}
	output := formatEdrEnumResults(results)
	if !strings.Contains(output, "Found 2 EDR/AV") {
		t.Errorf("should say 'Found 2', got: %s", output)
	}
	if !strings.Contains(output, "WinDefend") {
		t.Error("should contain WinDefend")
	}
	if !strings.Contains(output, "CrowdStrike") {
		t.Error("should contain CrowdStrike")
	}
}

func TestEdrCrowdStrikePresent(t *testing.T) {
	found := false
	for _, entry := range edrKnownServices {
		if entry.Vendor == "CrowdStrike" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CrowdStrike should be in the database")
	}
}

func TestEdrSentinelOnePresent(t *testing.T) {
	found := false
	for _, entry := range edrKnownServices {
		if entry.Vendor == "SentinelOne" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SentinelOne should be in the database")
	}
}
