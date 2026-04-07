package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
)

func TestRemoteSvcStateName(t *testing.T) {
	tests := []struct {
		state    uint32
		expected string
	}{
		{svcStateStopped, "STOPPED"},
		{svcStateStartPending, "START_PENDING"},
		{svcStateStopPending, "STOP_PENDING"},
		{svcStateRunning, "RUNNING"},
		{svcStateContinuePending, "CONTINUE_PENDING"},
		{svcStatePausePending, "PAUSE_PENDING"},
		{svcStatePaused, "PAUSED"},
		{99, "UNKNOWN(99)"},
	}

	for _, tc := range tests {
		result := remoteSvcStateName(tc.state)
		if result != tc.expected {
			t.Errorf("remoteSvcStateName(%d) = %q, want %q", tc.state, result, tc.expected)
		}
	}
}

func TestRemoteSvcTypeName(t *testing.T) {
	tests := []struct {
		svcType  uint32
		expected string
	}{
		{svcWin32OwnProcess, "WIN32_OWN_PROCESS"},
		{svcWin32ShareProcess, "WIN32_SHARE_PROCESS"},
		{svcWin32OwnProcess | svcWin32ShareProcess, "WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS"},
		{1, "KERNEL_DRIVER"},
		{2, "FILE_SYSTEM_DRIVER"},
		{0x04, "TYPE(0x4)"},
	}

	for _, tc := range tests {
		result := remoteSvcTypeName(tc.svcType)
		if result != tc.expected {
			t.Errorf("remoteSvcTypeName(0x%x) = %q, want %q", tc.svcType, result, tc.expected)
		}
	}
}

func TestRemoteSvcStartTypeName(t *testing.T) {
	tests := []struct {
		startType uint32
		expected  string
	}{
		{svcStartBoot, "BOOT_START"},
		{svcStartSystem, "SYSTEM_START"},
		{svcStartAuto, "AUTO_START"},
		{svcStartDemand, "DEMAND_START"},
		{svcStartDisabled, "DISABLED"},
		{99, "START_TYPE(99)"},
	}

	for _, tc := range tests {
		result := remoteSvcStartTypeName(tc.startType)
		if result != tc.expected {
			t.Errorf("remoteSvcStartTypeName(%d) = %q, want %q", tc.startType, result, tc.expected)
		}
	}
}

func TestParseStartType(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"auto", svcStartAuto},
		{"AUTO", svcStartAuto},
		{"demand", svcStartDemand},
		{"manual", svcStartDemand},
		{"disabled", svcStartDisabled},
		{"", svcStartDemand},
		{"unknown", svcStartDemand},
	}

	for _, tc := range tests {
		result := parseStartType(tc.input)
		if result != tc.expected {
			t.Errorf("parseStartType(%q) = %d, want %d", tc.input, result, tc.expected)
		}
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hell…"},
		{"ab", 2, "ab"},
		{"abc", 2, "a…"},
	}

	for _, tc := range tests {
		result := truncateStr(tc.input, tc.maxLen)
		if result != tc.expected {
			t.Errorf("truncateStr(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
		}
	}
}

func TestReadUTF16StringFromBuf(t *testing.T) {
	// Build a buffer with a UTF-16LE "Spooler\x00" at offset 0
	str := "Spooler"
	encoded := utf16.Encode([]rune(str))
	buf := make([]byte, (len(encoded)+1)*2)
	for i, ch := range encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], ch)
	}
	// null terminator already zero

	result := readUTF16StringFromBuf(buf, 0)
	if result != str {
		t.Errorf("readUTF16StringFromBuf = %q, want %q", result, str)
	}

	// Test at an offset
	offset := uint32(20)
	buf2 := make([]byte, int(offset)+(len(encoded)+1)*2)
	for i, ch := range encoded {
		binary.LittleEndian.PutUint16(buf2[int(offset)+i*2:], ch)
	}
	result2 := readUTF16StringFromBuf(buf2, offset)
	if result2 != str {
		t.Errorf("readUTF16StringFromBuf at offset = %q, want %q", result2, str)
	}

	// Out of bounds returns empty
	result3 := readUTF16StringFromBuf(buf, uint32(len(buf)+10))
	if result3 != "" {
		t.Errorf("readUTF16StringFromBuf out of bounds = %q, want empty", result3)
	}
}

func TestRemoteServiceCommand_Name(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	if cmd.Name() != "remote-service" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "remote-service")
	}
}

func TestRemoteServiceCommand_Description(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestRemoteServiceCommand_EmptyParams(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("empty params should show usage, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "Usage:") {
		t.Error("expected usage text in output")
	}
}

func TestRemoteServiceCommand_UnknownAction(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid","server":"host"}`})
	if result.Status != "error" {
		t.Errorf("unknown action should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_MissingCredentials(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list","server":"host","username":"user"}`})
	if result.Status != "error" {
		t.Errorf("missing credentials should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "password") && !strings.Contains(result.Output, "hash") {
		t.Error("error should mention password or hash requirement")
	}
}

func TestRemoteServiceCommand_QueryNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"query","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("query without name should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "-name") {
		t.Error("error should mention -name requirement")
	}
}

func TestRemoteServiceCommand_CreateNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"create","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("create without name should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_CreateNoBinpath(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"create","server":"host","name":"test","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("create without binpath should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "-binpath") {
		t.Error("error should mention -binpath requirement")
	}
}

func TestRemoteServiceCommand_StartNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"start","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("start without name should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_StopNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"stop","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("stop without name should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_DeleteNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"delete","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("delete without name should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_ListUnreachable(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list","server":"192.0.2.1","username":"user","password":"pass","timeout":1}`})
	if result.Status != "error" {
		t.Errorf("list to unreachable host should error, got status=%q", result.Status)
	}
}

// Tests for advanced actions (modify-path, trigger, dll-sideload)

func TestParseTriggerType(t *testing.T) {
	tests := []struct {
		input       string
		wantType    uint32
		wantContain string // substring of description
	}{
		{"network", svcTriggerTypeIPAddress, "Network Availability"},
		{"", svcTriggerTypeIPAddress, "Network Availability"}, // default
		{"unknown", svcTriggerTypeIPAddress, "Network Availability"}, // default
		{"domain-join", svcTriggerTypeDomainJoin, "Domain Join"},
		{"domain_join", svcTriggerTypeDomainJoin, "Domain Join"},
		{"domainjoin", svcTriggerTypeDomainJoin, "Domain Join"},
		{"firewall", svcTriggerTypeFirewall, "Firewall"},
		{"firewall-open", svcTriggerTypeFirewall, "Firewall"},
		{"firewall_open", svcTriggerTypeFirewall, "Firewall"},
		{"group-policy", svcTriggerTypeGroupPolicy, "Group Policy"},
		{"group_policy", svcTriggerTypeGroupPolicy, "Group Policy"},
		{"grouppolicy", svcTriggerTypeGroupPolicy, "Group Policy"},
		{"gpo", svcTriggerTypeGroupPolicy, "Group Policy"},
	}

	for _, tc := range tests {
		trigType, guid, desc := parseTriggerType(tc.input)
		if trigType != tc.wantType {
			t.Errorf("parseTriggerType(%q) type = %d, want %d", tc.input, trigType, tc.wantType)
		}
		if guid == nil {
			t.Errorf("parseTriggerType(%q) returned nil GUID", tc.input)
		}
		if !strings.Contains(desc, tc.wantContain) {
			t.Errorf("parseTriggerType(%q) desc = %q, want to contain %q", tc.input, desc, tc.wantContain)
		}
	}
}

func TestEncodeDecodeRegSZ(t *testing.T) {
	tests := []string{
		"C:\\Windows\\System32\\svchost.dll",
		"%SystemRoot%\\System32\\wuaueng.dll",
		"",
		"short",
		"path with spaces and special chars!@#$%",
	}

	for _, s := range tests {
		encoded := encodeRegSZ(s)
		decoded := decodeRegSZ(encoded)
		if decoded != s {
			t.Errorf("round-trip for %q: got %q", s, decoded)
		}
	}
}

func TestDecodeRegSZ_ShortBuffer(t *testing.T) {
	// Empty buffer
	if got := decodeRegSZ(nil); got != "" {
		t.Errorf("decodeRegSZ(nil) = %q, want empty", got)
	}
	// Single byte (too short for UTF-16)
	if got := decodeRegSZ([]byte{0x41}); got != "" {
		t.Errorf("decodeRegSZ(1 byte) = %q, want empty", got)
	}
}

func TestEncodeRegSZ_NullTerminated(t *testing.T) {
	encoded := encodeRegSZ("AB")
	// "AB" = 0x41,0x00, 0x42,0x00, 0x00,0x00 (null terminator)
	if len(encoded) != 6 {
		t.Errorf("encodeRegSZ(\"AB\") length = %d, want 6", len(encoded))
	}
	// Last two bytes should be null terminator
	if encoded[4] != 0 || encoded[5] != 0 {
		t.Errorf("encodeRegSZ should be null-terminated, got %v", encoded[4:6])
	}
}

func TestRemoteServiceCommand_ModifyPathNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"modify-path","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("modify-path without name should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "-name") {
		t.Error("error should mention -name requirement")
	}
}

func TestRemoteServiceCommand_ModifyPathNoBinpath(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"modify-path","server":"host","name":"svc","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("modify-path without binpath should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "-binpath") {
		t.Error("error should mention -binpath requirement")
	}
}

func TestRemoteServiceCommand_TriggerNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"trigger","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("trigger without name should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_TriggerNoBinpath(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"trigger","server":"host","name":"svc","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("trigger without binpath should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_DLLSideloadNoName(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"dll-sideload","server":"host","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("dll-sideload without name should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_DLLSideloadNoBinpath(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"dll-sideload","server":"host","name":"svc","username":"user","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("dll-sideload without binpath should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_ModifyPathUnreachable(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"modify-path","server":"192.0.2.1","name":"svc","binpath":"C:\\test.exe","username":"user","password":"pass","timeout":1}`})
	if result.Status != "error" {
		t.Errorf("modify-path to unreachable should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_TriggerUnreachable(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"trigger","server":"192.0.2.1","name":"svc","binpath":"C:\\test.exe","username":"user","password":"pass","timeout":1}`})
	if result.Status != "error" {
		t.Errorf("trigger to unreachable should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_DLLSideloadUnreachable(t *testing.T) {
	cmd := &RemoteServiceCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"dll-sideload","server":"192.0.2.1","name":"svc","binpath":"C:\\test.dll","username":"user","password":"pass","timeout":1}`})
	if result.Status != "error" {
		t.Errorf("dll-sideload to unreachable should error, got status=%q", result.Status)
	}
}

func TestRemoteServiceCommand_ActionRouting(t *testing.T) {
	// Verify both hyphen and underscore variants route to the same action
	cmd := &RemoteServiceCommand{}
	for _, action := range []string{"modify-path", "modify_path", "dll-sideload", "dll_sideload"} {
		result := cmd.Execute(structs.Task{Params: fmt.Sprintf(`{"action":"%s","server":"host","username":"user","password":"pass"}`, action)})
		// Should get parameter validation error, not "unknown action"
		if strings.Contains(result.Output, "Unknown action") {
			t.Errorf("action %q should be recognized but got unknown action error", action)
		}
	}
}

func TestTriggerGUIDs(t *testing.T) {
	// Verify GUIDs are non-nil and have correct Data4 length
	guids := []*dtyp.GUID{guidNetworkFirstIP, guidDomainJoin, guidFirewallOpen, guidMachinePolicy}
	names := []string{"guidNetworkFirstIP", "guidDomainJoin", "guidFirewallOpen", "guidMachinePolicy"}
	for i, g := range guids {
		if g == nil {
			t.Errorf("%s is nil", names[i])
			continue
		}
		if len(g.Data4) != 8 {
			t.Errorf("%s Data4 length = %d, want 8", names[i], len(g.Data4))
		}
		if g.Data1 == 0 {
			t.Errorf("%s Data1 should not be zero", names[i])
		}
	}
}

func TestSvcNoChangeConstant(t *testing.T) {
	// SERVICE_NO_CHANGE must be 0xFFFFFFFF
	if svcNoChange != 0xFFFFFFFF {
		t.Errorf("svcNoChange = 0x%x, want 0xFFFFFFFF", svcNoChange)
	}
}
