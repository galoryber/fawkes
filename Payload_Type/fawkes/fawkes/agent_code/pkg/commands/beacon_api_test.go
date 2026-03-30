//go:build windows

package commands

import (
	"testing"
	"unsafe"
)

func TestDataParserStructLayout(t *testing.T) {
	// DataParser should have 4 fields matching Cobalt Strike's datap struct
	var dp DataParser
	// Verify the struct is properly sized (4 fields: uintptr, uintptr, int32, int32)
	// On 64-bit: 8 + 8 + 4 + 4 = 24 bytes
	// On 32-bit: 4 + 4 + 4 + 4 = 16 bytes
	size := unsafe.Sizeof(dp)
	if size == 0 {
		t.Error("DataParser size should not be 0")
	}
	// On amd64 (our primary target), should be 24 bytes
	if unsafe.Sizeof(uintptr(0)) == 8 && size != 24 {
		t.Errorf("DataParser size on 64-bit = %d, want 24", size)
	}
}

func TestDataParserFieldOffsets(t *testing.T) {
	var dp DataParser
	// Verify field order and offsets match expected layout
	originalOffset := unsafe.Offsetof(dp.original)
	bufferOffset := unsafe.Offsetof(dp.buffer)
	lengthOffset := unsafe.Offsetof(dp.length)
	sizeOffset := unsafe.Offsetof(dp.size)

	if originalOffset != 0 {
		t.Errorf("original offset = %d, want 0", originalOffset)
	}
	if bufferOffset <= originalOffset {
		t.Error("buffer should come after original")
	}
	if lengthOffset <= bufferOffset {
		t.Error("length should come after buffer")
	}
	if sizeOffset <= lengthOffset {
		t.Error("size should come after length")
	}
}

func TestBOFConstants(t *testing.T) {
	if bofMemCommit != 0x1000 {
		t.Errorf("bofMemCommit = 0x%x, want 0x1000", bofMemCommit)
	}
	if bofMemReserve != 0x2000 {
		t.Errorf("bofMemReserve = 0x%x, want 0x2000", bofMemReserve)
	}
	if bofMemTopDown != 0x100000 {
		t.Errorf("bofMemTopDown = 0x%x, want 0x100000", bofMemTopDown)
	}
}
