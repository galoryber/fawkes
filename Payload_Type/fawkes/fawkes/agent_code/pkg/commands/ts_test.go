//go:build windows

package commands

import (
	"encoding/json"
	"testing"
	"unsafe"
)

func TestTsCommandName(t *testing.T) {
	assertCommandName(t, &TsCommand{}, "ts")
}

func TestTsCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &TsCommand{})
}

func TestTsEmptyParams(t *testing.T) {
	cmd := &TsCommand{}
	// Empty params should NOT error — defaults to listing all threads
	result := cmd.Execute(mockTask("ts", ""))
	// The command will try to enumerate threads; may succeed or fail
	// depending on environment, but shouldn't panic
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestTsJSONParams(t *testing.T) {
	cmd := &TsCommand{}
	params, _ := json.Marshal(TsArgs{All: true, PID: 99999})
	result := cmd.Execute(mockTask("ts", string(params)))
	// PID 99999 likely doesn't exist, but should not panic
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestTsArgsStruct(t *testing.T) {
	var args TsArgs
	data := `{"all": true, "pid": 1234}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if !args.All {
		t.Error("expected All=true")
	}
	if args.PID != 1234 {
		t.Errorf("expected PID=1234, got %d", args.PID)
	}
}

func TestTsWaitReasonConstants(t *testing.T) {
	tests := []struct {
		reason KWAIT_REASON
		name   string
	}{
		{Executive, "Executive"},
		{DelayExecution, "DelayExecution"},
		{Suspended, "Suspended"},
		{UserRequest, "UserRequest"},
		{WrQueue, "WrQueue"},
		{WrAlertByThreadId, "WrAlertByThreadId"},
	}
	for _, tc := range tests {
		got := getWaitReasonString(tc.reason)
		if got != tc.name {
			t.Errorf("getWaitReasonString(%d) = %q, want %q", tc.reason, got, tc.name)
		}
	}
}

func TestTsStructSizes(t *testing.T) {
	// THREADENTRY32 should be 28 bytes
	if size := unsafe.Sizeof(THREADENTRY32{}); size != 28 {
		t.Errorf("THREADENTRY32 size = %d, want 28", size)
	}
}

func TestTsProcessThreadInfoFields(t *testing.T) {
	info := ProcessThreadInfo{
		PID:   1234,
		Name:  "test.exe",
		Arch:  "x64",
		Owner: "SYSTEM",
		Threads: []ThreadInfo{
			{ThreadID: 5678, WaitReason: "Executive"},
		},
	}
	if info.PID != 1234 {
		t.Error("PID mismatch")
	}
	if len(info.Threads) != 1 {
		t.Error("expected 1 thread")
	}
	if info.Threads[0].ThreadID != 5678 {
		t.Error("thread ID mismatch")
	}
}
