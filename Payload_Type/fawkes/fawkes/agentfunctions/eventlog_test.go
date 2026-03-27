package agentfunctions

import "testing"

func TestIsFilePath_UnixAbsolute(t *testing.T) {
	if !isFilePath("/var/log/syslog") {
		t.Error("expected true for Unix absolute path")
	}
}

func TestIsFilePath_WindowsDrive(t *testing.T) {
	if !isFilePath(`C:\Windows\System32\winevt\Logs`) {
		t.Error("expected true for Windows drive path")
	}
}

func TestIsFilePath_UNCPath(t *testing.T) {
	if !isFilePath(`\\server\share\file.evtx`) {
		t.Error("expected true for UNC path")
	}
}

func TestIsFilePath_RelativePath(t *testing.T) {
	if isFilePath("relative/path") {
		t.Error("expected false for relative path")
	}
}

func TestIsFilePath_ChannelName(t *testing.T) {
	if isFilePath("Application") {
		t.Error("expected false for channel name")
	}
	if isFilePath("Microsoft-Windows-Sysmon/Operational") {
		t.Error("expected false for channel with slash (no leading /)")
	}
}

func TestIsFilePath_Empty(t *testing.T) {
	if isFilePath("") {
		t.Error("expected false for empty string")
	}
}

func TestIsFilePath_SingleSlash(t *testing.T) {
	if !isFilePath("/") {
		t.Error("expected true for root path")
	}
}

func TestIsFilePath_BackslashOnly(t *testing.T) {
	if isFilePath(`\not\unc`) {
		t.Error("expected false for single backslash prefix (not UNC)")
	}
}
