//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// buildTestPE creates a synthetic PE byte array for testing.
// The PE has a valid DOS header, PE signature, file header, and optional header.
func buildTestPE(isDLL bool, hasClrHeader bool) []byte {
	// DOS header is 64 bytes, PE sig at offset 64
	const ntOffset = 64
	fileHeaderSize := int(unsafe.Sizeof(imageFileHeader{}))
	optHeaderSize := int(unsafe.Sizeof(rlOptionalHeader64{}))

	totalSize := ntOffset + 4 + fileHeaderSize + optHeaderSize + 256 // extra padding
	pe := make([]byte, totalSize)

	// DOS header
	binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D)   // MZ magic
	binary.LittleEndian.PutUint32(pe[60:64], ntOffset) // ELfanew

	// PE signature
	binary.LittleEndian.PutUint32(pe[ntOffset:ntOffset+4], 0x00004550)

	// File header (starts at ntOffset + 4)
	fhOffset := ntOffset + 4
	binary.LittleEndian.PutUint16(pe[fhOffset+0:fhOffset+2], 0x8664) // Machine: AMD64
	binary.LittleEndian.PutUint16(pe[fhOffset+2:fhOffset+4], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(pe[fhOffset+16:fhOffset+18], uint16(optHeaderSize)) // SizeOfOptionalHeader

	chars := uint16(0x0022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	if isDLL {
		chars |= 0x2000 // IMAGE_FILE_DLL
	}
	binary.LittleEndian.PutUint16(pe[fhOffset+18:fhOffset+20], chars) // Characteristics

	// Optional header (starts at fhOffset + fileHeaderSize)
	ohOffset := fhOffset + fileHeaderSize
	binary.LittleEndian.PutUint16(pe[ohOffset:ohOffset+2], 0x020B) // PE32+ magic
	binary.LittleEndian.PutUint32(pe[ohOffset+108:ohOffset+112], 16) // NumberOfRvaAndSizes

	if hasClrHeader {
		// Data directory entry 14 = COM_DESCRIPTOR (CLR header)
		// Each entry is 8 bytes (VirtualAddress + Size), starting at offset 112
		clrDirOffset := ohOffset + 112 + 14*8
		binary.LittleEndian.PutUint32(pe[clrDirOffset:clrDirOffset+4], 0x2000)   // VirtualAddress (non-zero)
		binary.LittleEndian.PutUint32(pe[clrDirOffset+4:clrDirOffset+8], 0x0048) // Size (non-zero)
	}

	return pe
}

// --- peLoaderIsDLL Tests ---

func TestPeLoaderIsDLL_True(t *testing.T) {
	pe := buildTestPE(true, false)
	if !peLoaderIsDLL(pe) {
		t.Error("peLoaderIsDLL should return true for DLL")
	}
}

func TestPeLoaderIsDLL_False(t *testing.T) {
	pe := buildTestPE(false, false)
	if peLoaderIsDLL(pe) {
		t.Error("peLoaderIsDLL should return false for EXE")
	}
}

func TestPeLoaderIsDLL_TooSmall(t *testing.T) {
	if peLoaderIsDLL([]byte{0x4D, 0x5A}) {
		t.Error("peLoaderIsDLL should return false for tiny data")
	}
}

func TestPeLoaderIsDLL_BadMagic(t *testing.T) {
	pe := buildTestPE(true, false)
	pe[0] = 0xFF // corrupt MZ magic
	if peLoaderIsDLL(pe) {
		t.Error("peLoaderIsDLL should return false with bad DOS magic")
	}
}

func TestPeLoaderIsDLL_EmptyData(t *testing.T) {
	if peLoaderIsDLL(nil) {
		t.Error("peLoaderIsDLL should return false for nil data")
	}
}

// --- peLoaderIsNETAssembly Tests ---

func TestPeLoaderIsNETAssembly_True(t *testing.T) {
	pe := buildTestPE(false, true)
	if !peLoaderIsNETAssembly(pe) {
		t.Error("peLoaderIsNETAssembly should return true when CLR header is present")
	}
}

func TestPeLoaderIsNETAssembly_False(t *testing.T) {
	pe := buildTestPE(false, false)
	if peLoaderIsNETAssembly(pe) {
		t.Error("peLoaderIsNETAssembly should return false for native PE")
	}
}

func TestPeLoaderIsNETAssembly_DLLWithCLR(t *testing.T) {
	pe := buildTestPE(true, true)
	if !peLoaderIsNETAssembly(pe) {
		t.Error("peLoaderIsNETAssembly should return true for .NET DLL")
	}
}

func TestPeLoaderIsNETAssembly_TooSmall(t *testing.T) {
	if peLoaderIsNETAssembly([]byte{0x4D, 0x5A}) {
		t.Error("peLoaderIsNETAssembly should return false for tiny data")
	}
}

func TestPeLoaderIsNETAssembly_BadMagic(t *testing.T) {
	pe := buildTestPE(false, true)
	pe[0] = 0xFF // corrupt MZ magic
	if peLoaderIsNETAssembly(pe) {
		t.Error("peLoaderIsNETAssembly should return false with bad DOS magic")
	}
}

func TestPeLoaderIsNETAssembly_BadPESig(t *testing.T) {
	pe := buildTestPE(false, true)
	pe[64] = 0x00 // corrupt PE signature
	if peLoaderIsNETAssembly(pe) {
		t.Error("peLoaderIsNETAssembly should return false with bad PE signature")
	}
}

func TestPeLoaderIsNETAssembly_EmptyData(t *testing.T) {
	if peLoaderIsNETAssembly(nil) {
		t.Error("peLoaderIsNETAssembly should return false for nil data")
	}
}

func TestPeLoaderIsNETAssembly_ZeroCLRSize(t *testing.T) {
	pe := buildTestPE(false, true)
	// Zero out CLR directory size (keep VirtualAddress non-zero)
	fileHeaderSize := int(unsafe.Sizeof(imageFileHeader{}))
	ohOffset := 64 + 4 + fileHeaderSize
	clrDirOffset := ohOffset + 112 + 14*8
	binary.LittleEndian.PutUint32(pe[clrDirOffset+4:clrDirOffset+8], 0) // Zero Size
	if peLoaderIsNETAssembly(pe) {
		t.Error("peLoaderIsNETAssembly should return false when CLR Size is 0")
	}
}
