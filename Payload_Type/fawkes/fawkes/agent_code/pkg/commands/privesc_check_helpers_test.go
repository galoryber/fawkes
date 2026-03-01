package commands

import (
	"os"
	"testing"
)

func TestIsUnquotedServicePath(t *testing.T) {
	// Note: extractExePath probes the filesystem, so on Linux the unquoted
	// Windows paths fall back to first space-delimited token. These tests
	// verify the quoting/filter logic that doesn't depend on the filesystem.
	tests := []struct {
		name     string
		binPath  string
		expected bool
	}{
		{"quoted path", `"C:\Program Files\service\svc.exe" -arg1`, false},
		{"no spaces", `C:\service\svc.exe`, false},
		{"svchost", `C:\Windows\system32\svchost.exe -k netsvcs`, false},
		{"system32 path", `C:\Windows\System32\spoolsv.exe`, false},
		{"empty", "", false},
		// Use a real path with spaces to test on Linux
		{"real path with space", "/tmp/test dir/service", true},
	}

	// Create a test directory with space to verify detection
	testDir := "/tmp/test dir"
	testFile := testDir + "/service"
	_ = os.MkdirAll(testDir, 0755)
	f, err := os.Create(testFile)
	if err != nil {
		t.Skip("Cannot create test file in /tmp")
	}
	f.Close()
	defer os.RemoveAll(testDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUnquotedServicePath(tt.binPath)
			if result != tt.expected {
				t.Errorf("isUnquotedServicePath(%q) = %v, want %v", tt.binPath, result, tt.expected)
			}
		})
	}
}

func TestExtractExePath(t *testing.T) {
	tests := []struct {
		name     string
		binPath  string
		expected string
	}{
		{"quoted path", `"C:\Program Files\svc.exe" -arg`, `C:\Program Files\svc.exe`},
		{"simple path", `C:\svc.exe`, `C:\svc.exe`},
		{"empty", "", ""},
		{"spaces only", "   ", ""},
		{"quoted no close", `"C:\path\svc.exe`, `C:\path\svc.exe`},
		{"path with args no space", `C:\svc.exe -flag`, `C:\svc.exe`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractExePath(tt.binPath)
			if result != tt.expected {
				t.Errorf("extractExePath(%q) = %q, want %q", tt.binPath, result, tt.expected)
			}
		})
	}
}

func TestStartTypeString(t *testing.T) {
	tests := []struct {
		st       uint32
		expected string
	}{
		{0, "Boot"},
		{1, "System"},
		{2, "Auto"},
		{3, "Manual"},
		{4, "Disabled"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := startTypeString(tt.st)
			if result != tt.expected {
				t.Errorf("startTypeString(%d) = %q, want %q", tt.st, result, tt.expected)
			}
		})
	}
}

func TestIsFileReadable(t *testing.T) {
	// /etc/passwd should be readable
	if !isFileReadable("/etc/passwd") {
		t.Error("Expected /etc/passwd to be readable")
	}
	// Non-existent file should not be readable
	if isFileReadable("/nonexistent/file/path") {
		t.Error("Expected non-existent file to not be readable")
	}
}

func TestIsDirWritable(t *testing.T) {
	// /tmp should be writable
	if !isDirWritable("/tmp") {
		t.Error("Expected /tmp to be writable")
	}
	// Non-existent dir should not be writable
	if isDirWritable("/nonexistent/dir/path") {
		t.Error("Expected non-existent dir to not be writable")
	}
}
