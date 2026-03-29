//go:build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestWriteMemoryCommandName(t *testing.T) {
	assertCommandName(t, &WriteMemoryCommand{}, "write-memory")
}

func TestWriteMemoryCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &WriteMemoryCommand{})
}

func TestWriteMemoryArgsUnmarshal(t *testing.T) {
	var args WriteMemoryArgs
	data := `{"dll_name":"ntdll.dll","function_name":"EtwEventWrite","start_index":0,"hex_bytes":"C3"}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.DllName != "ntdll.dll" {
		t.Errorf("DllName = %q, want ntdll.dll", args.DllName)
	}
	if args.FunctionName != "EtwEventWrite" {
		t.Errorf("FunctionName = %q, want EtwEventWrite", args.FunctionName)
	}
	if args.HexBytes != "C3" {
		t.Errorf("HexBytes = %q, want C3", args.HexBytes)
	}
}

func TestWriteMemoryInvalidParams(t *testing.T) {
	cmd := &WriteMemoryCommand{}
	result := cmd.Execute(mockTask("write-memory", "only two args"))
	assertError(t, result)
}

func TestWriteMemoryInvalidHex(t *testing.T) {
	cmd := &WriteMemoryCommand{}
	params, _ := json.Marshal(WriteMemoryArgs{
		DllName:      "ntdll.dll",
		FunctionName: "EtwEventWrite",
		StartIndex:   0,
		HexBytes:     "ZZZZ",
	})
	result := cmd.Execute(mockTask("write-memory", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "hex")
}

func TestWriteMemoryInvalidDLL(t *testing.T) {
	cmd := &WriteMemoryCommand{}
	params, _ := json.Marshal(WriteMemoryArgs{
		DllName:      "nonexistent_dll_xyz.dll",
		FunctionName: "SomeFunc",
		StartIndex:   0,
		HexBytes:     "90",
	})
	result := cmd.Execute(mockTask("write-memory", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "loading DLL")
}

func TestHexDecodeValid(t *testing.T) {
	bytes, err := hex.DecodeString("4C8BD1B8")
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	if len(bytes) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(bytes))
	}
	if bytes[0] != 0x4C {
		t.Errorf("byte[0] = 0x%X, want 0x4C", bytes[0])
	}
}
