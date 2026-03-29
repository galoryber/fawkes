//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestReadMemoryCommandName(t *testing.T) {
	assertCommandName(t, &ReadMemoryCommand{}, "read-memory")
}

func TestReadMemoryCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &ReadMemoryCommand{})
}

func TestReadMemoryArgsUnmarshal(t *testing.T) {
	var args ReadMemoryArgs
	data := `{"dll_name":"ntdll.dll","function_name":"NtWriteVirtualMemory","start_index":0,"num_bytes":16}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.DllName != "ntdll.dll" {
		t.Errorf("DllName = %q, want ntdll.dll", args.DllName)
	}
	if args.FunctionName != "NtWriteVirtualMemory" {
		t.Errorf("FunctionName = %q, want NtWriteVirtualMemory", args.FunctionName)
	}
	if args.StartIndex != 0 {
		t.Errorf("StartIndex = %d, want 0", args.StartIndex)
	}
	if args.NumBytes != 16 {
		t.Errorf("NumBytes = %d, want 16", args.NumBytes)
	}
}

func TestReadMemoryInvalidParams(t *testing.T) {
	cmd := &ReadMemoryCommand{}
	result := cmd.Execute(mockTask("read-memory", "only two args"))
	assertError(t, result)
}

func TestReadMemoryInvalidDLL(t *testing.T) {
	cmd := &ReadMemoryCommand{}
	params, _ := json.Marshal(ReadMemoryArgs{
		DllName:      "nonexistent_dll_xyz.dll",
		FunctionName: "SomeFunc",
		StartIndex:   0,
		NumBytes:     4,
	})
	result := cmd.Execute(mockTask("read-memory", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "loading DLL")
}

func TestReadMemoryValidDLL(t *testing.T) {
	cmd := &ReadMemoryCommand{}
	params, _ := json.Marshal(ReadMemoryArgs{
		DllName:      "ntdll.dll",
		FunctionName: "NtClose",
		StartIndex:   0,
		NumBytes:     8,
	})
	result := cmd.Execute(mockTask("read-memory", string(params)))
	assertSuccess(t, result)
	assertOutputContains(t, result, "Read 8 bytes")
	assertOutputContains(t, result, "ntdll.dll!NtClose")
}
