//go:build linux

package commands

import (
	"strings"
	"testing"
)

// --- parseOSRelease tests ---

func TestParseOSRelease_Ubuntu(t *testing.T) {
	content := `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
`
	result := parseOSRelease(content)

	if result["NAME"] != "Ubuntu" {
		t.Errorf("expected NAME 'Ubuntu', got %q", result["NAME"])
	}
	if result["ID"] != "ubuntu" {
		t.Errorf("expected ID 'ubuntu', got %q", result["ID"])
	}
	if result["PRETTY_NAME"] != "Ubuntu 22.04.3 LTS" {
		t.Errorf("expected PRETTY_NAME 'Ubuntu 22.04.3 LTS', got %q", result["PRETTY_NAME"])
	}
	if result["VERSION_ID"] != "22.04" {
		t.Errorf("expected VERSION_ID '22.04', got %q", result["VERSION_ID"])
	}
	if result["ID_LIKE"] != "debian" {
		t.Errorf("expected ID_LIKE 'debian', got %q", result["ID_LIKE"])
	}
}

func TestParseOSRelease_CentOS(t *testing.T) {
	content := `NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
PRETTY_NAME="CentOS Linux 7 (Core)"
`
	result := parseOSRelease(content)

	if result["NAME"] != "CentOS Linux" {
		t.Errorf("expected NAME 'CentOS Linux', got %q", result["NAME"])
	}
	if result["ID"] != "centos" {
		t.Errorf("expected ID 'centos', got %q", result["ID"])
	}
}

func TestParseOSRelease_EmptyInput(t *testing.T) {
	result := parseOSRelease("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestParseOSRelease_CommentsAndBlanks(t *testing.T) {
	content := `# This is a comment
NAME="Test"

# Another comment
ID=test

`
	result := parseOSRelease(content)
	if result["NAME"] != "Test" {
		t.Errorf("expected NAME 'Test', got %q", result["NAME"])
	}
	if result["ID"] != "test" {
		t.Errorf("expected ID 'test', got %q", result["ID"])
	}
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
}

func TestParseOSRelease_NoQuotes(t *testing.T) {
	content := `NAME=Alpine
ID=alpine
VERSION_ID=3.18
`
	result := parseOSRelease(content)
	if result["NAME"] != "Alpine" {
		t.Errorf("expected NAME 'Alpine', got %q", result["NAME"])
	}
}

func TestParseOSRelease_MalformedLine(t *testing.T) {
	content := `NAME="Valid"
malformed_line_no_equals
ID=test
`
	result := parseOSRelease(content)
	if result["NAME"] != "Valid" {
		t.Errorf("expected NAME 'Valid', got %q", result["NAME"])
	}
	if result["ID"] != "test" {
		t.Errorf("expected ID 'test', got %q", result["ID"])
	}
	if len(result) != 2 {
		t.Errorf("expected 2 entries (skipping malformed), got %d", len(result))
	}
}

func TestParseOSRelease_ValueWithEquals(t *testing.T) {
	content := `HOME_URL="https://example.com/?key=value&foo=bar"
`
	result := parseOSRelease(content)
	if result["HOME_URL"] != "https://example.com/?key=value&foo=bar" {
		t.Errorf("expected URL with equals signs preserved, got %q", result["HOME_URL"])
	}
}

// --- parseMeminfo tests ---

func TestParseMeminfo_Standard(t *testing.T) {
	content := `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
Cached:          4096000 kB
SwapTotal:       8192000 kB
SwapFree:        8192000 kB
`
	result := parseMeminfo(content)

	if result["MemTotal"] != "16384000 kB" {
		t.Errorf("expected MemTotal '16384000 kB', got %q", result["MemTotal"])
	}
	if result["MemAvailable"] != "8192000 kB" {
		t.Errorf("expected MemAvailable '8192000 kB', got %q", result["MemAvailable"])
	}
	if result["SwapTotal"] != "8192000 kB" {
		t.Errorf("expected SwapTotal '8192000 kB', got %q", result["SwapTotal"])
	}
}

func TestParseMeminfo_EmptyInput(t *testing.T) {
	result := parseMeminfo("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestParseMeminfo_MalformedLines(t *testing.T) {
	content := `MemTotal:       16384000 kB
no_colon_here
MemFree:        2048000 kB
`
	result := parseMeminfo(content)
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
	if result["MemTotal"] != "16384000 kB" {
		t.Errorf("expected MemTotal '16384000 kB', got %q", result["MemTotal"])
	}
}

func TestParseMeminfo_WhitespaceHandling(t *testing.T) {
	content := `MemTotal:       16384000 kB
HugePages_Total:       0
`
	result := parseMeminfo(content)
	if result["MemTotal"] != "16384000 kB" {
		t.Errorf("expected trimmed value, got %q", result["MemTotal"])
	}
	if result["HugePages_Total"] != "0" {
		t.Errorf("expected '0', got %q", result["HugePages_Total"])
	}
}

// --- collectPlatformSysinfo live test ---

func TestCollectPlatformSysinfo_Live(t *testing.T) {
	var sb strings.Builder
	collectPlatformSysinfo(&sb)
	output := sb.String()

	if output == "" {
		t.Fatal("expected non-empty output from collectPlatformSysinfo")
	}
	if !strings.Contains(output, "Linux Details") {
		t.Error("expected 'Linux Details' header")
	}
	// Should contain UID (always available)
	if !strings.Contains(output, "UID:") {
		t.Error("expected UID in output")
	}
	if !strings.Contains(output, "EUID:") {
		t.Error("expected EUID in output")
	}
	if !strings.Contains(output, "GID:") {
		t.Error("expected GID in output")
	}
	// On most Linux systems, /proc/version and /proc/meminfo exist
	if !strings.Contains(output, "Kernel:") {
		t.Error("expected Kernel in output")
	}
	if !strings.Contains(output, "Total Memory:") {
		t.Error("expected Total Memory in output")
	}
}
