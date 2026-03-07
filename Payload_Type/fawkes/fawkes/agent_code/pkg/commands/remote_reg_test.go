package commands

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	winreg "github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

func TestRemoteRegTypeName(t *testing.T) {
	tests := []struct {
		typeVal  uint32
		expected string
	}{
		{winreg.RegString, "REG_SZ"},
		{winreg.RegExpandString, "REG_EXPAND_SZ"},
		{winreg.RegBinary, "REG_BINARY"},
		{winreg.RegDword, "REG_DWORD"},
		{winreg.RegMultistring, "REG_MULTI_SZ"},
		{winreg.RegQword, "REG_QWORD"},
		{99, "TYPE(99)"},
	}

	for _, tc := range tests {
		result := remoteRegTypeName(tc.typeVal)
		if result != tc.expected {
			t.Errorf("remoteRegTypeName(%d) = %q, want %q", tc.typeVal, result, tc.expected)
		}
	}
}

func TestEncodeRemoteRegValue_SZ(t *testing.T) {
	valType, data, err := encodeRemoteRegValue("hello", "REG_SZ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valType != winreg.RegString {
		t.Errorf("type = %d, want %d", valType, winreg.RegString)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestEncodeRemoteRegValue_DWORD(t *testing.T) {
	valType, data, err := encodeRemoteRegValue("42", "REG_DWORD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valType != winreg.RegDword {
		t.Errorf("type = %d, want %d", valType, winreg.RegDword)
	}
	if len(data) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(data))
	}
	val := binary.LittleEndian.Uint32(data)
	if val != 42 {
		t.Errorf("value = %d, want 42", val)
	}
}

func TestEncodeRemoteRegValue_DWORDHex(t *testing.T) {
	valType, data, err := encodeRemoteRegValue("0xFF", "REG_DWORD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valType != winreg.RegDword {
		t.Errorf("type = %d, want %d", valType, winreg.RegDword)
	}
	val := binary.LittleEndian.Uint32(data)
	if val != 255 {
		t.Errorf("value = %d, want 255", val)
	}
}

func TestEncodeRemoteRegValue_QWORD(t *testing.T) {
	valType, data, err := encodeRemoteRegValue("1234567890", "REG_QWORD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valType != winreg.RegQword {
		t.Errorf("type = %d, want %d", valType, winreg.RegQword)
	}
	if len(data) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(data))
	}
	val := binary.LittleEndian.Uint64(data)
	if val != 1234567890 {
		t.Errorf("value = %d, want 1234567890", val)
	}
}

func TestEncodeRemoteRegValue_BINARY(t *testing.T) {
	valType, data, err := encodeRemoteRegValue("deadbeef", "REG_BINARY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valType != winreg.RegBinary {
		t.Errorf("type = %d, want %d", valType, winreg.RegBinary)
	}
	expected, _ := hex.DecodeString("deadbeef")
	if string(data) != string(expected) {
		t.Errorf("data = %x, want %x", data, expected)
	}
}

func TestEncodeRemoteRegValue_EXPAND_SZ(t *testing.T) {
	valType, _, err := encodeRemoteRegValue("%SystemRoot%\\test", "REG_EXPAND_SZ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valType != winreg.RegExpandString {
		t.Errorf("type = %d, want %d", valType, winreg.RegExpandString)
	}
}

func TestEncodeRemoteRegValue_InvalidType(t *testing.T) {
	_, _, err := encodeRemoteRegValue("test", "REG_INVALID")
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestEncodeRemoteRegValue_InvalidDWORD(t *testing.T) {
	_, _, err := encodeRemoteRegValue("notanumber", "REG_DWORD")
	if err == nil {
		t.Error("expected error for invalid DWORD value")
	}
}

func TestEncodeRemoteRegValue_InvalidBinary(t *testing.T) {
	_, _, err := encodeRemoteRegValue("not-hex", "REG_BINARY")
	if err == nil {
		t.Error("expected error for invalid binary data")
	}
}

func TestFormatRemoteRegValueShort_DWORD(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 255)
	result := formatRemoteRegValueShort(winreg.RegDword, data)
	if result != "255 (0xFF)" {
		t.Errorf("formatRemoteRegValueShort(DWORD, 255) = %q", result)
	}
}

func TestFormatRemoteRegValueShort_QWORD(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, 42)
	result := formatRemoteRegValueShort(winreg.RegQword, data)
	if result != "42 (0x2A)" {
		t.Errorf("formatRemoteRegValueShort(QWORD, 42) = %q", result)
	}
}

func TestFormatRemoteRegValueShort_Binary(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	result := formatRemoteRegValueShort(winreg.RegBinary, data)
	if result != "deadbeef" {
		t.Errorf("formatRemoteRegValueShort(BINARY) = %q, want deadbeef", result)
	}
}

func TestFormatRemoteRegValue_DWORD(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 1)
	result := formatRemoteRegValue("TestVal", winreg.RegDword, data)
	if result == "" {
		t.Error("expected non-empty formatted output")
	}
	if !strings.Contains(result, "TestVal") || !strings.Contains(result, "1") || !strings.Contains(result, "REG_DWORD") {
		t.Errorf("formatted output missing expected content: %q", result)
	}
}

func TestRemoteRegCommand_Name(t *testing.T) {
	cmd := &RemoteRegCommand{}
	if cmd.Name() != "remote-reg" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "remote-reg")
	}
}

func TestRemoteRegCommand_Description(t *testing.T) {
	cmd := &RemoteRegCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestRemoteRegCommand_EmptyParams(t *testing.T) {
	cmd := &RemoteRegCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("empty params should show usage, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "Usage:") {
		t.Error("expected usage text in output")
	}
}

func TestRemoteRegCommand_UnknownAction(t *testing.T) {
	cmd := &RemoteRegCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid","server":"host"}`})
	if result.Status != "error" {
		t.Errorf("unknown action should error, got status=%q", result.Status)
	}
}

func TestRemoteRegCommand_MissingCredentials(t *testing.T) {
	cmd := &RemoteRegCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"enum","server":"host","username":"user"}`})
	if result.Status != "error" {
		t.Errorf("missing credentials should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "password") && !strings.Contains(result.Output, "hash") {
		t.Error("error should mention password or hash requirement")
	}
}

func TestRemoteRegCommand_QueryUnreachable(t *testing.T) {
	cmd := &RemoteRegCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"query","server":"192.0.2.1","username":"user","password":"pass","timeout":1}`})
	if result.Status != "error" {
		t.Errorf("query to unreachable host should error, got status=%q", result.Status)
	}
}
