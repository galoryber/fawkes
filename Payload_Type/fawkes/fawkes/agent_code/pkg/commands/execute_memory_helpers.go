package commands

import "encoding/binary"

// isValidPE checks for valid PE signatures (MZ header + PE signature at NT header offset).
// This is a pure validation function with no platform dependencies.
func isValidPE(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	// Check DOS signature "MZ"
	if binary.LittleEndian.Uint16(data[0:2]) != 0x5A4D {
		return false
	}

	// Read e_lfanew (offset to NT headers) at offset 0x3C
	ntOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if ntOffset == 0 || int(ntOffset)+4 > len(data) {
		return false
	}

	// Check PE signature "PE\0\0"
	if binary.LittleEndian.Uint32(data[ntOffset:ntOffset+4]) != 0x00004550 {
		return false
	}

	return true
}
