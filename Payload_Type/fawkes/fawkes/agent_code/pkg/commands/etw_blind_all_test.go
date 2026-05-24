//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEtwBlindAll_RequiresProvider(t *testing.T) {
	result := etwBlindAll("")
	if result.Status != "error" {
		t.Errorf("Expected error for empty provider, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "provider is required") {
		t.Errorf("Expected 'provider is required' message, got %q", result.Output)
	}
}

func TestEtwBlindAll_UnknownProvider(t *testing.T) {
	result := etwBlindAll("not-a-real-provider-xyz")
	if result.Status != "error" {
		t.Errorf("Expected error for unknown provider, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Could not resolve") {
		t.Errorf("Expected 'Could not resolve' message, got %q", result.Output)
	}
}

func TestEtwBlindAll_ViaDispatch(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "blind-all"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("blind-all without provider should error, got %s", result.Status)
	}
}

func TestEtwBlindAll_DispatchAcceptsShorthand(t *testing.T) {
	// Confirms the dispatcher routes "blind-all" to etwBlindAll and that
	// a shorthand provider name resolves successfully past the validation
	// gate. The actual EnumerateTraceGuidsEx call may succeed or fail
	// depending on whether the provider is registered on the test host —
	// we just check we got past the resolveProviderGUID step.
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "blind-all", Provider: "sysmon"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if strings.Contains(result.Output, "Could not resolve") {
		t.Errorf("Sysmon shorthand should resolve, got %q", result.Output)
	}
}

func TestParseProviderLoggerIDs_EmptyData(t *testing.T) {
	loggerIDs, instances := parseProviderLoggerIDs(nil)
	if instances != 0 {
		t.Errorf("Expected 0 instances for nil data, got %d", instances)
	}
	if len(loggerIDs) != 0 {
		t.Errorf("Expected 0 loggerIDs for nil data, got %d", len(loggerIDs))
	}
}

func TestParseProviderLoggerIDs_ShortData(t *testing.T) {
	loggerIDs, instances := parseProviderLoggerIDs(make([]byte, 4))
	if instances != 0 || len(loggerIDs) != 0 {
		t.Errorf("Expected zero results for short data, got %d / %d", instances, len(loggerIDs))
	}
}

func TestParseProviderLoggerIDs_ZeroInstances(t *testing.T) {
	data := make([]byte, 8) // header only, InstanceCount=0
	loggerIDs, instances := parseProviderLoggerIDs(data)
	if instances != 0 || len(loggerIDs) != 0 {
		t.Errorf("Expected zero results, got %d / %d", instances, len(loggerIDs))
	}
}

func TestParseProviderLoggerIDs_OneEnabledSession(t *testing.T) {
	// header(8) + instance(16) + enable(24) = 48 bytes
	data := make([]byte, 8+16+24)

	// TRACE_GUID_INFO: InstanceCount=1
	binary.LittleEndian.PutUint32(data[0:4], 1)

	// TRACE_PROVIDER_INSTANCE_INFO at +8: NextOffset=0, EnableCount=1, Pid=0xCAFE, Flags=0
	binary.LittleEndian.PutUint32(data[8:12], 0)
	binary.LittleEndian.PutUint32(data[12:16], 1)
	binary.LittleEndian.PutUint32(data[16:20], 0xCAFE)

	// TRACE_ENABLE_INFO at +24: IsEnabled=1, Level=4, LoggerId=42
	binary.LittleEndian.PutUint32(data[24:28], 1)
	data[28] = 4 // Level
	binary.LittleEndian.PutUint16(data[30:32], 42)

	loggerIDs, instances := parseProviderLoggerIDs(data)
	if instances != 1 {
		t.Errorf("Expected 1 instance, got %d", instances)
	}
	if len(loggerIDs) != 1 || loggerIDs[0] != 42 {
		t.Errorf("Expected loggerIDs=[42], got %v", loggerIDs)
	}
}

func TestParseProviderLoggerIDs_DisabledIsSkipped(t *testing.T) {
	data := make([]byte, 8+16+24)
	binary.LittleEndian.PutUint32(data[0:4], 1)
	binary.LittleEndian.PutUint32(data[12:16], 1) // EnableCount=1
	// IsEnabled=0 — should be skipped
	binary.LittleEndian.PutUint32(data[24:28], 0)
	binary.LittleEndian.PutUint16(data[30:32], 99)

	loggerIDs, instances := parseProviderLoggerIDs(data)
	if instances != 1 {
		t.Errorf("Expected instance count of 1 (instance present, just disabled), got %d", instances)
	}
	if len(loggerIDs) != 0 {
		t.Errorf("Expected 0 loggerIDs for disabled enable record, got %v", loggerIDs)
	}
}

func TestParseProviderLoggerIDs_DedupAcrossInstances(t *testing.T) {
	// Two instances both reporting LoggerID=7 — should appear once in output.
	const header = 8
	const instSize = 16
	const enSize = 24
	data := make([]byte, header+(instSize+enSize)*2)

	binary.LittleEndian.PutUint32(data[0:4], 2) // InstanceCount=2

	// First instance — NextOffset = instSize+enSize
	off := header
	binary.LittleEndian.PutUint32(data[off:off+4], uint32(instSize+enSize))
	binary.LittleEndian.PutUint32(data[off+4:off+8], 1) // EnableCount=1
	binary.LittleEndian.PutUint32(data[off+16:off+20], 1) // IsEnabled
	binary.LittleEndian.PutUint16(data[off+22:off+24], 7) // LoggerId=7

	// Second instance
	off += instSize + enSize
	binary.LittleEndian.PutUint32(data[off:off+4], 0)   // NextOffset=0
	binary.LittleEndian.PutUint32(data[off+4:off+8], 1) // EnableCount=1
	binary.LittleEndian.PutUint32(data[off+16:off+20], 1)
	binary.LittleEndian.PutUint16(data[off+22:off+24], 7) // same LoggerId=7

	loggerIDs, instances := parseProviderLoggerIDs(data)
	if instances != 2 {
		t.Errorf("Expected 2 instances, got %d", instances)
	}
	if len(loggerIDs) != 1 || loggerIDs[0] != 7 {
		t.Errorf("Expected dedup'd loggerIDs=[7], got %v", loggerIDs)
	}
}

func TestParseProviderLoggerIDs_MultipleDistinctSessions(t *testing.T) {
	// One instance with two enable records (provider enabled in two different sessions).
	const header = 8
	const instSize = 16
	const enSize = 24
	data := make([]byte, header+instSize+enSize*2)

	binary.LittleEndian.PutUint32(data[0:4], 1)

	off := header
	binary.LittleEndian.PutUint32(data[off:off+4], 0)
	binary.LittleEndian.PutUint32(data[off+4:off+8], 2) // EnableCount=2

	// Enable #1: LoggerId=10
	binary.LittleEndian.PutUint32(data[off+16:off+20], 1)
	binary.LittleEndian.PutUint16(data[off+22:off+24], 10)
	// Enable #2: LoggerId=20
	binary.LittleEndian.PutUint32(data[off+16+enSize:off+20+enSize], 1)
	binary.LittleEndian.PutUint16(data[off+22+enSize:off+24+enSize], 20)

	loggerIDs, _ := parseProviderLoggerIDs(data)
	if len(loggerIDs) != 2 {
		t.Fatalf("Expected 2 distinct logger IDs, got %v", loggerIDs)
	}
	got := map[int]bool{loggerIDs[0]: true, loggerIDs[1]: true}
	if !got[10] || !got[20] {
		t.Errorf("Expected loggerIDs to contain {10,20}, got %v", loggerIDs)
	}
}

func TestParseLoggerName_EmptyBuffer(t *testing.T) {
	if got := parseLoggerName(nil); got != "" {
		t.Errorf("Expected empty string for nil buffer, got %q", got)
	}
	if got := parseLoggerName(make([]byte, 64)); got != "" {
		t.Errorf("Expected empty string for short buffer, got %q", got)
	}
}

func TestParseLoggerName_ZeroOffset(t *testing.T) {
	buf := make([]byte, eventTracePropsSize)
	// LoggerNameOffset @ 116 left as zero — should yield ""
	if got := parseLoggerName(buf); got != "" {
		t.Errorf("Expected empty string for zero offset, got %q", got)
	}
}

func TestParseLoggerName_DecodesUTF16(t *testing.T) {
	buf := make([]byte, eventTracePropsSize)
	// Write a UTF-16LE name "EventLog" at offset 200 with NUL terminator
	binary.LittleEndian.PutUint32(buf[116:120], 200)
	name := "EventLog"
	for i, ch := range name {
		binary.LittleEndian.PutUint16(buf[200+i*2:202+i*2], uint16(ch))
	}
	// Trailing 0 already present from make()

	if got := parseLoggerName(buf); got != "EventLog" {
		t.Errorf("Expected 'EventLog', got %q", got)
	}
}
