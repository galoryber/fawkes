package commands

import (
	"encoding/binary"
	"testing"
)

// buildMinimalPE creates a minimal valid PE binary for testing.
// The PE has: DOS header (64 bytes) + PE signature + minimal file header.
func buildMinimalPE() []byte {
	pe := make([]byte, 128)

	// DOS header
	binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D)   // e_magic = "MZ"
	binary.LittleEndian.PutUint32(pe[0x3C:0x40], 0x40) // e_lfanew = 64

	// PE signature at offset 0x40
	binary.LittleEndian.PutUint32(pe[0x40:0x44], 0x00004550) // "PE\0\0"

	// Minimal IMAGE_FILE_HEADER at 0x44
	binary.LittleEndian.PutUint16(pe[0x44:0x46], 0x8664) // Machine: AMD64

	return pe
}

func TestIsValidPE_ValidMinimalPE(t *testing.T) {
	pe := buildMinimalPE()
	if !isValidPE(pe) {
		t.Error("expected valid PE to be recognized")
	}
}

func TestIsValidPE_ValidPE32(t *testing.T) {
	pe := buildMinimalPE()
	// Change machine to i386
	binary.LittleEndian.PutUint16(pe[0x44:0x46], 0x014C)
	if !isValidPE(pe) {
		t.Error("expected 32-bit PE to be valid")
	}
}

func TestIsValidPE_TooSmall(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x4D}},
		{"2 bytes MZ", []byte{0x4D, 0x5A}},
		{"63 bytes", make([]byte, 63)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isValidPE(tt.data) {
				t.Error("expected too-small data to be invalid")
			}
		})
	}
}

func TestIsValidPE_BadMZSignature(t *testing.T) {
	pe := buildMinimalPE()
	pe[0] = 0x00 // Corrupt MZ
	pe[1] = 0x00
	if isValidPE(pe) {
		t.Error("expected PE with bad MZ signature to be invalid")
	}
}

func TestIsValidPE_ELFBinary(t *testing.T) {
	// ELF magic: 0x7F 'E' 'L' 'F'
	elf := make([]byte, 128)
	elf[0] = 0x7F
	elf[1] = 'E'
	elf[2] = 'L'
	elf[3] = 'F'
	if isValidPE(elf) {
		t.Error("expected ELF binary to be rejected as invalid PE")
	}
}

func TestIsValidPE_MachOBinary(t *testing.T) {
	macho := make([]byte, 128)
	// Mach-O magic: 0xCFFA EDFE (little-endian)
	macho[0] = 0xCF
	macho[1] = 0xFA
	macho[2] = 0xED
	macho[3] = 0xFE
	if isValidPE(macho) {
		t.Error("expected Mach-O binary to be rejected as invalid PE")
	}
}

func TestIsValidPE_BadNTOffset(t *testing.T) {
	tests := []struct {
		name     string
		ntOffset uint32
	}{
		{"zero offset", 0},
		{"offset beyond data", 200},
		{"offset at end minus 3", 125}, // need 4 bytes but only 3 left
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pe := make([]byte, 128)
			binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D) // MZ
			binary.LittleEndian.PutUint32(pe[0x3C:0x40], tt.ntOffset)
			if isValidPE(pe) {
				t.Errorf("expected PE with NT offset %d to be invalid", tt.ntOffset)
			}
		})
	}
}

func TestIsValidPE_BadPESignature(t *testing.T) {
	pe := buildMinimalPE()
	// Corrupt PE signature
	binary.LittleEndian.PutUint32(pe[0x40:0x44], 0xDEADBEEF)
	if isValidPE(pe) {
		t.Error("expected PE with bad PE signature to be invalid")
	}
}

func TestIsValidPE_NTOffsetAtEdge(t *testing.T) {
	// Create data where NT offset points to exactly the last 4 bytes
	pe := make([]byte, 68)
	binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D)    // MZ
	binary.LittleEndian.PutUint32(pe[0x3C:0x40], 64)   // e_lfanew = 64
	binary.LittleEndian.PutUint32(pe[64:68], 0x00004550) // PE signature
	if !isValidPE(pe) {
		t.Error("expected PE with NT offset at exact edge to be valid")
	}
}

func TestIsValidPE_LargeNTOffset(t *testing.T) {
	// Some PE packers use large e_lfanew values
	pe := make([]byte, 512)
	binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D)      // MZ
	binary.LittleEndian.PutUint32(pe[0x3C:0x40], 0x100)  // e_lfanew = 256
	binary.LittleEndian.PutUint32(pe[0x100:0x104], 0x00004550) // PE sig at 256
	if !isValidPE(pe) {
		t.Error("expected PE with large NT offset to be valid")
	}
}

func TestIsValidPE_AllZeros(t *testing.T) {
	data := make([]byte, 128)
	if isValidPE(data) {
		t.Error("expected all-zeros data to be invalid PE")
	}
}

func TestIsValidPE_RandomData(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	// Pad to 64 bytes
	padded := make([]byte, 64)
	copy(padded, data)
	if isValidPE(padded) {
		t.Error("expected random data to be invalid PE")
	}
}
