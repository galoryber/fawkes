package commands

import (
	"strings"
	"testing"
)

// --- tccAuthValueStr Tests ---

func TestTccAuthValueStr(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "Denied"},
		{1, "Unknown"},
		{2, "Allowed"},
		{3, "Limited"},
		{99, "Unknown(99)"},
		{-1, "Unknown(-1)"},
	}
	for _, tc := range tests {
		got := tccAuthValueStr(tc.input)
		if got != tc.want {
			t.Errorf("tccAuthValueStr(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- tccAuthReasonStr Tests ---

func TestTccAuthReasonStr(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "Error"},
		{1, "User Consent"},
		{2, "User Set"},
		{3, "System Set"},
		{4, "Service Policy"},
		{5, "MDM Policy"},
		{6, "Override Policy"},
		{7, "Missing Usage String"},
		{8, "Prompt Timeout"},
		{9, "Preflight Unknown"},
		{10, "Entitled"},
		{11, "App Type Policy"},
		{42, "Unknown(42)"},
	}
	for _, tc := range tests {
		got := tccAuthReasonStr(tc.input)
		if got != tc.want {
			t.Errorf("tccAuthReasonStr(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- tccClientTypeStr Tests ---

func TestTccClientTypeStr(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "Bundle ID"},
		{1, "Absolute Path"},
		{2, "Unknown(2)"},
		{-1, "Unknown(-1)"},
	}
	for _, tc := range tests {
		got := tccClientTypeStr(tc.input)
		if got != tc.want {
			t.Errorf("tccClientTypeStr(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- tccServiceNames Tests ---

func TestTccServiceNames_KnownKeys(t *testing.T) {
	knownKeys := []struct {
		key  string
		want string
	}{
		{"kTCCServiceCamera", "Camera"},
		{"kTCCServiceMicrophone", "Microphone"},
		{"kTCCServiceScreenCapture", "Screen Recording"},
		{"kTCCServiceSystemPolicyAllFiles", "Full Disk Access"},
		{"kTCCServiceAccessibility", "Accessibility"},
	}
	for _, tc := range knownKeys {
		got, ok := tccServiceNames[tc.key]
		if !ok {
			t.Errorf("tccServiceNames[%q] missing", tc.key)
			continue
		}
		if got != tc.want {
			t.Errorf("tccServiceNames[%q] = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestTccServiceNames_Coverage(t *testing.T) {
	// Ensure the map has a reasonable number of entries
	if len(tccServiceNames) < 30 {
		t.Errorf("tccServiceNames has %d entries, expected at least 30", len(tccServiceNames))
	}
}

// --- formatTCCOutput Tests ---

func TestFormatTCCOutput_Empty(t *testing.T) {
	output := formatTCCOutput(nil, "", "/user/db", "/system/db")
	if !strings.Contains(output, "Records:   0") {
		t.Error("empty entries should show 0 records")
	}
	if !strings.Contains(output, "no allowed permissions found") {
		t.Error("empty entries should show no allowed permissions")
	}
}

func TestFormatTCCOutput_WithEntries(t *testing.T) {
	entries := []tccEntry{
		{
			Service:     "kTCCServiceCamera",
			ServiceName: "Camera",
			Client:      "com.example.app",
			ClientType:  0,
			AuthValue:   2, // Allowed
			AuthReason:  1, // User Consent
			Source:      "user",
		},
		{
			Service:     "kTCCServiceMicrophone",
			ServiceName: "Microphone",
			Client:      "/usr/bin/app",
			ClientType:  1,
			AuthValue:   0, // Denied
			AuthReason:  3, // System Set
			Source:      "system",
		},
	}

	output := formatTCCOutput(entries, "", "/user/db", "/system/db")
	if !strings.Contains(output, "Records:   2") {
		t.Error("should show 2 records")
	}
	if !strings.Contains(output, "--- Camera ---") {
		t.Error("should contain Camera section")
	}
	if !strings.Contains(output, "--- Microphone ---") {
		t.Error("should contain Microphone section")
	}
	if !strings.Contains(output, "[Allowed] com.example.app") {
		t.Error("should show allowed status for camera app")
	}
	if !strings.Contains(output, "[Denied] /usr/bin/app") {
		t.Error("should show denied status for microphone app")
	}
	if !strings.Contains(output, "Allowed Permissions Summary") {
		t.Error("should contain summary section")
	}
	if !strings.Contains(output, "Camera: com.example.app") {
		t.Error("summary should list allowed camera permission")
	}
}

func TestFormatTCCOutput_WithFilter(t *testing.T) {
	output := formatTCCOutput(nil, "Camera", "/user/db", "/system/db")
	if !strings.Contains(output, "Filter:    Camera") {
		t.Error("should show filter value")
	}
}

func TestFormatTCCOutput_GroupsByService(t *testing.T) {
	entries := []tccEntry{
		{ServiceName: "Camera", Client: "app1", AuthValue: 2, AuthReason: 1, Source: "user"},
		{ServiceName: "Camera", Client: "app2", AuthValue: 0, AuthReason: 1, Source: "user"},
		{ServiceName: "Microphone", Client: "app3", AuthValue: 2, AuthReason: 1, Source: "system"},
	}

	output := formatTCCOutput(entries, "", "/u", "/s")
	// Camera section should appear before Microphone (insertion order)
	cameraIdx := strings.Index(output, "--- Camera ---")
	micIdx := strings.Index(output, "--- Microphone ---")
	if cameraIdx == -1 || micIdx == -1 {
		t.Fatal("missing section headers")
	}
	if cameraIdx > micIdx {
		t.Error("Camera should appear before Microphone (insertion order)")
	}
}
