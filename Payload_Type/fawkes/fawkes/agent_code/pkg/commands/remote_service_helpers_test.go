package commands

import (
	"strings"
	"testing"
)

// --- remoteSvcStateName tests ---

func TestRemoteSvcStateName_KnownStates(t *testing.T) {
	cases := []struct {
		state uint32
		want  string
	}{
		{svcStateStopped, "STOPPED"},
		{svcStateStartPending, "START_PENDING"},
		{svcStateStopPending, "STOP_PENDING"},
		{svcStateRunning, "RUNNING"},
		{svcStateContinuePending, "CONTINUE_PENDING"},
		{svcStatePausePending, "PAUSE_PENDING"},
		{svcStatePaused, "PAUSED"},
	}
	for _, tc := range cases {
		got := remoteSvcStateName(tc.state)
		if got != tc.want {
			t.Errorf("remoteSvcStateName(%d) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestRemoteSvcStateName_Unknown(t *testing.T) {
	got := remoteSvcStateName(99)
	if !strings.HasPrefix(got, "UNKNOWN") {
		t.Errorf("unknown state = %q, want UNKNOWN prefix", got)
	}
	if !strings.Contains(got, "99") {
		t.Errorf("unknown state = %q, want state value 99 in output", got)
	}
}

// --- remoteSvcTypeName tests ---

func TestRemoteSvcTypeName_Win32OwnProcess(t *testing.T) {
	got := remoteSvcTypeName(svcWin32OwnProcess)
	if got != "WIN32_OWN_PROCESS" {
		t.Errorf("WIN32_OWN_PROCESS = %q", got)
	}
}

func TestRemoteSvcTypeName_Win32ShareProcess(t *testing.T) {
	got := remoteSvcTypeName(svcWin32ShareProcess)
	if got != "WIN32_SHARE_PROCESS" {
		t.Errorf("WIN32_SHARE_PROCESS = %q", got)
	}
}

func TestRemoteSvcTypeName_BothWin32(t *testing.T) {
	got := remoteSvcTypeName(svcWin32OwnProcess | svcWin32ShareProcess)
	if !strings.Contains(got, "WIN32_OWN_PROCESS") || !strings.Contains(got, "WIN32_SHARE_PROCESS") {
		t.Errorf("both WIN32 types = %q", got)
	}
}

func TestRemoteSvcTypeName_KernelDriver(t *testing.T) {
	got := remoteSvcTypeName(1)
	if got != "KERNEL_DRIVER" {
		t.Errorf("KERNEL_DRIVER type = %q", got)
	}
}

func TestRemoteSvcTypeName_FileSystemDriver(t *testing.T) {
	got := remoteSvcTypeName(2)
	if got != "FILE_SYSTEM_DRIVER" {
		t.Errorf("FILE_SYSTEM_DRIVER type = %q", got)
	}
}

func TestRemoteSvcTypeName_Unknown(t *testing.T) {
	// 0x04 has no WIN32 bits (0x10, 0x20) and is not 1 or 2
	got := remoteSvcTypeName(0x04)
	if !strings.HasPrefix(got, "TYPE(") {
		t.Errorf("unknown type = %q, want TYPE(...) prefix", got)
	}
}

// --- remoteSvcStartTypeName tests ---

func TestRemoteSvcStartTypeName_KnownTypes(t *testing.T) {
	cases := []struct {
		t    uint32
		want string
	}{
		{svcStartBoot, "BOOT_START"},
		{svcStartSystem, "SYSTEM_START"},
		{svcStartAuto, "AUTO_START"},
		{svcStartDemand, "DEMAND_START"},
		{svcStartDisabled, "DISABLED"},
	}
	for _, tc := range cases {
		got := remoteSvcStartTypeName(tc.t)
		if got != tc.want {
			t.Errorf("remoteSvcStartTypeName(%d) = %q, want %q", tc.t, got, tc.want)
		}
	}
}

func TestRemoteSvcStartTypeName_Unknown(t *testing.T) {
	got := remoteSvcStartTypeName(99)
	if !strings.HasPrefix(got, "START_TYPE") {
		t.Errorf("unknown start type = %q, want START_TYPE prefix", got)
	}
}

// --- parseStartType tests ---

func TestParseStartType_Auto(t *testing.T) {
	if got := parseStartType("auto"); got != svcStartAuto {
		t.Errorf("auto = %d, want %d", got, svcStartAuto)
	}
}

func TestParseStartType_Disabled(t *testing.T) {
	if got := parseStartType("disabled"); got != svcStartDisabled {
		t.Errorf("disabled = %d, want %d", got, svcStartDisabled)
	}
}

func TestParseStartType_Demand(t *testing.T) {
	if got := parseStartType("demand"); got != svcStartDemand {
		t.Errorf("demand = %d, want %d", got, svcStartDemand)
	}
}

func TestParseStartType_Manual(t *testing.T) {
	if got := parseStartType("manual"); got != svcStartDemand {
		t.Errorf("manual = %d, want demand (%d)", got, svcStartDemand)
	}
}

func TestParseStartType_Empty(t *testing.T) {
	if got := parseStartType(""); got != svcStartDemand {
		t.Errorf("empty = %d, want demand (%d)", got, svcStartDemand)
	}
}

func TestParseStartType_Unknown(t *testing.T) {
	if got := parseStartType("unknown_type"); got != svcStartDemand {
		t.Errorf("unknown = %d, want demand (%d)", got, svcStartDemand)
	}
}

func TestParseStartType_CaseInsensitive(t *testing.T) {
	if got := parseStartType("AUTO"); got != svcStartAuto {
		t.Errorf("AUTO (uppercase) = %d, want %d", got, svcStartAuto)
	}
}

// --- truncateStr tests ---

func TestTruncateStr_ShortString(t *testing.T) {
	got := truncateStr("hello", 10)
	if got != "hello" {
		t.Errorf("short string = %q, want unchanged", got)
	}
}

func TestTruncateStr_ExactLength(t *testing.T) {
	got := truncateStr("hello", 5)
	if got != "hello" {
		t.Errorf("exact length = %q, want unchanged", got)
	}
}

func TestTruncateStr_Truncated(t *testing.T) {
	got := truncateStr("hello world", 8)
	if len([]rune(got)) > 8 {
		t.Errorf("truncated length = %d, want <= 8", len(got))
	}
	// Should end with ellipsis character
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated = %q, want ellipsis suffix", got)
	}
}

func TestTruncateStr_Empty(t *testing.T) {
	got := truncateStr("", 5)
	if got != "" {
		t.Errorf("empty = %q, want empty", got)
	}
}

// --- readUTF16StringFromBuf tests ---

func TestReadUTF16StringFromBuf_ASCII(t *testing.T) {
	// "AB" in UTF-16LE: 0x41 0x00 0x42 0x00 0x00 0x00
	buf := []byte{0x41, 0x00, 0x42, 0x00, 0x00, 0x00}
	got := readUTF16StringFromBuf(buf, 0)
	if got != "AB" {
		t.Errorf("readUTF16StringFromBuf = %q, want AB", got)
	}
}

func TestReadUTF16StringFromBuf_WithOffset(t *testing.T) {
	// Prefix + "Hi" in UTF-16LE
	buf := []byte{0xff, 0xff, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00}
	got := readUTF16StringFromBuf(buf, 2)
	if got != "Hi" {
		t.Errorf("readUTF16StringFromBuf at offset 2 = %q, want Hi", got)
	}
}

func TestReadUTF16StringFromBuf_Empty(t *testing.T) {
	buf := []byte{0x00, 0x00}
	got := readUTF16StringFromBuf(buf, 0)
	if got != "" {
		t.Errorf("empty UTF-16 = %q, want empty", got)
	}
}

func TestReadUTF16StringFromBuf_OffsetOutOfBounds(t *testing.T) {
	buf := []byte{0x41, 0x00}
	got := readUTF16StringFromBuf(buf, 10)
	if got != "" {
		t.Errorf("out-of-bounds offset = %q, want empty", got)
	}
}
