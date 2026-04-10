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

func TestExtractExePath_ExeSuffixCheck(t *testing.T) {
	// When the path doesn't end with .exe and the file exists with .exe appended,
	// we should find the .exe version. Create a temp file with .exe suffix.
	dir := t.TempDir()
	exePath := dir + "/myprogram.exe"
	os.WriteFile(exePath, []byte("binary"), 0755)

	// Input without .exe suffix and with arguments — should find the .exe version
	result := extractExePath(dir + "/myprogram some args")
	if result != exePath {
		t.Errorf("expected %q, got %q", exePath, result)
	}
}

func TestExtractExePath_ExeSuffixSkipWhenAlreadyExe(t *testing.T) {
	// When path already ends with .exe, should NOT try appending .exe again
	result := extractExePath("/nonexistent/path.exe arg1 arg2")
	// Falls back to first space-delimited token
	if result != "/nonexistent/path.exe" {
		t.Errorf("expected /nonexistent/path.exe, got %q", result)
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

func TestIsUnquotedServicePath_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		binPath  string
		expected bool
	}{
		{"double-quoted empty", `""`, false},
		{"single char", "a", false},
		{"just a quote", `"`, false},
		{"svchost mixed case", `C:\Windows\SYSTEM32\SVCHOST.EXE -k netsvcs`, false},
		{"system32 lowercase", `c:\windows\system32\svc.exe`, false},
		{"path with backslashes no spaces", `C:\MyApp\service.exe -run`, false},
		{"multiple args", `C:\service.exe arg1 arg2 arg3`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUnquotedServicePath(tt.binPath)
			if result != tt.expected {
				t.Errorf("isUnquotedServicePath(%q) = %v, want %v", tt.binPath, result, tt.expected)
			}
		})
	}
}

func TestExtractExePath_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		binPath  string
		expected string
	}{
		{"tab prefix", "\tC:\\svc.exe", `C:\svc.exe`},
		{"newline in path", "C:\\svc.exe\n", `C:\svc.exe`},
		{"quoted with trailing space", `"C:\path\svc.exe"  `, `C:\path\svc.exe`},
		{"backslash only", `\`, `\`},
		{"forward slashes", "/usr/bin/service -d", "/usr/bin/service"},
		{"multiple spaces between args", `C:\svc.exe  arg1  arg2`, `C:\svc.exe`},
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

func TestStartTypeString_AllValues(t *testing.T) {
	// Verify exhaustive coverage of all Windows service start types
	expected := map[uint32]string{
		0:  "Boot",
		1:  "System",
		2:  "Auto",
		3:  "Manual",
		4:  "Disabled",
		5:  "Unknown(5)",
		10: "Unknown(10)",
	}
	for st, exp := range expected {
		result := startTypeString(st)
		if result != exp {
			t.Errorf("startTypeString(%d) = %q, want %q", st, result, exp)
		}
	}
}

func TestIsFileReadable_TempFile(t *testing.T) {
	// Create a temp file and verify it's readable
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "readable-test")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	if !isFileReadable(f.Name()) {
		t.Errorf("expected temp file %s to be readable", f.Name())
	}

	// Remove the file and check again
	os.Remove(f.Name())
	if isFileReadable(f.Name()) {
		t.Error("expected deleted file to not be readable")
	}
}

func TestIsDirWritable_TempDir(t *testing.T) {
	dir := t.TempDir()
	if !isDirWritable(dir) {
		t.Errorf("expected temp dir %s to be writable", dir)
	}
}

func TestExtractExePath_ExistingFileWithSpaces(t *testing.T) {
	// Create a file with spaces in the path
	dir := t.TempDir()
	spacedDir := dir + "/my app"
	os.MkdirAll(spacedDir, 0755)
	exePath := spacedDir + "/service.exe"
	os.WriteFile(exePath, []byte("binary"), 0755)

	// Test that extractExePath finds the file with spaces when it exists
	result := extractExePath(spacedDir + "/service.exe --flag")
	if result != exePath {
		t.Errorf("expected %q, got %q", exePath, result)
	}
}
