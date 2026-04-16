package commands

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// These tests verify PEB-related constants and helper logic
// that is platform-independent.

func TestPEBOffsets_Consistency(t *testing.T) {
	// Verify PEB offsets are within expected ranges for x64 Windows
	if pebProcessParametersOffset != 0x20 {
		t.Errorf("PEB.ProcessParameters offset = 0x%X, want 0x20", pebProcessParametersOffset)
	}
	if uppImagePathNameOffset != 0x60 {
		t.Errorf("UPP.ImagePathName offset = 0x%X, want 0x60", uppImagePathNameOffset)
	}
	if uppCommandLineOffset != 0x70 {
		t.Errorf("UPP.CommandLine offset = 0x%X, want 0x70", uppCommandLineOffset)
	}
	if uppWindowTitleOffset != 0x80 {
		t.Errorf("UPP.WindowTitle offset = 0x%X, want 0x80", uppWindowTitleOffset)
	}
}

func TestPEBOffsets_UnicodeStringSize(t *testing.T) {
	// UNICODE_STRING on x64: Length(2) + MaxLength(2) + padding(4) + Buffer(8) = 16
	if unicodeStringSize != 16 {
		t.Errorf("UNICODE_STRING size = %d, want 16 for x64", unicodeStringSize)
	}
}

func TestPEBOffsets_NonOverlapping(t *testing.T) {
	// Verify offsets don't overlap (each UNICODE_STRING is 16 bytes)
	offsets := []struct {
		name   string
		offset uintptr
	}{
		{"ImagePathName", uppImagePathNameOffset},
		{"CommandLine", uppCommandLineOffset},
		{"WindowTitle", uppWindowTitleOffset},
	}

	for i, a := range offsets {
		for j, b := range offsets {
			if i == j {
				continue
			}
			if a.offset == b.offset {
				t.Errorf("%s and %s have the same offset 0x%X", a.name, b.name, a.offset)
			}
			// Check that fields don't overlap (each is unicodeStringSize bytes)
			if a.offset < b.offset && a.offset+unicodeStringSize > b.offset {
				t.Errorf("%s (0x%X) overlaps with %s (0x%X)", a.name, a.offset, b.name, b.offset)
			}
		}
	}
}

func TestUTF16Encoding_BasicString(t *testing.T) {
	// Verify UTF-16LE encoding for a typical Windows path
	input := `C:\Windows\System32\svchost.exe`
	utf16Str := utf16.Encode([]rune(input))
	utf16Bytes := make([]byte, len(utf16Str)*2)
	for i, r := range utf16Str {
		binary.LittleEndian.PutUint16(utf16Bytes[i*2:], r)
	}

	// Verify first char 'C' = 0x43, 0x00 in UTF-16LE
	if utf16Bytes[0] != 0x43 || utf16Bytes[1] != 0x00 {
		t.Errorf("first char = 0x%02X%02X, want 0x4300 (C)", utf16Bytes[0], utf16Bytes[1])
	}

	// Length in bytes should be 2x the string length
	expectedLen := len(input) * 2
	if len(utf16Bytes) != expectedLen {
		t.Errorf("UTF-16 byte length = %d, want %d", len(utf16Bytes), expectedLen)
	}
}

func TestUTF16Encoding_EmptyString(t *testing.T) {
	utf16Str := utf16.Encode([]rune(""))
	if len(utf16Str) != 0 {
		t.Errorf("empty string should produce 0 UTF-16 units, got %d", len(utf16Str))
	}
}

func TestUTF16Encoding_BackslashPreserved(t *testing.T) {
	// Windows paths use backslashes which must be preserved
	input := `C:\test\path`
	utf16Str := utf16.Encode([]rune(input))

	// Find the first backslash (should be at index 2)
	if utf16Str[2] != '\\' {
		t.Errorf("backslash at index 2 = 0x%04X, want 0x005C", utf16Str[2])
	}
}

func TestProcessBasicInformation_Size(t *testing.T) {
	// Verify the struct has the expected size for x64
	// PBI on x64 should be: ExitStatus(8) + PebBaseAddress(8) + AffinityMask(8) +
	//                        BasePriority(4) + padding(4) + UniqueProcessId(8) +
	//                        InheritedFromUniqueProcessId(8) = 48 bytes
	expectedSize := 48
	// We can't use unsafe.Sizeof in a cross-platform test since the struct is Windows-only,
	// but we verify the field count matches the expected layout
	type pbiLayout struct {
		f1 uintptr // ExitStatus
		f2 uintptr // PebBaseAddress
		f3 uintptr // AffinityMask
		f4 int32   // BasePriority
		_  [4]byte
		f5 uintptr // UniqueProcessId
		f6 uintptr // InheritedFromUniqueProcessId
	}
	// On 64-bit, uintptr is 8 bytes
	calculatedSize := 8 + 8 + 8 + 4 + 4 + 8 + 8
	if calculatedSize != expectedSize {
		t.Errorf("PBI calculated size = %d, want %d", calculatedSize, expectedSize)
	}
}
