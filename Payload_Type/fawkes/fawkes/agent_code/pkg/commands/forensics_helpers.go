package commands

// forensics_helpers.go — Cross-platform parsing/formatting helpers extracted from
// Windows-only forensics commands (amcache, prefetch, usnjrnl, laps).
// This file has no build constraints so these functions can be tested on CI.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// --- Windows FILETIME conversion ---

// filetimeToTime converts a Windows FILETIME (100-ns intervals since 1601-01-01) to Go time.
func filetimeToTime(ft int64) time.Time {
	const epochDiff = 11644473600
	seconds := ft/10000000 - epochDiff
	return time.Unix(seconds, 0).UTC()
}

// --- Shimcache (AppCompatCache) parsing ---

// shimcacheEntry represents a parsed entry from the Windows Shimcache
type shimcacheEntry struct {
	Path         string
	LastModified time.Time
	DataSize     uint32
	DataOffset   int
	EntrySize    int
}

// shimcacheWin10Sig is the Windows 10/11 entry signature "10ts" as little-endian uint32
const shimcacheWin10Sig = 0x73743031

// parseShimcacheWin10 parses Windows 10/11 Shimcache format.
// Header: first 4 bytes = header size (0x34 = 52 on Win10/11).
// Entries start at offset indicated by header size.
// Each entry: sig(4) + unknown(4) + data_size(4) + data(data_size bytes).
// Inside data: path_len(2) + path(path_len bytes UTF-16LE) + FILETIME(8) + remaining.
func parseShimcacheWin10(data []byte) ([]shimcacheEntry, error) {
	if len(data) < 52 {
		return nil, fmt.Errorf("data too small: %d bytes", len(data))
	}

	// Header size is in the first 4 bytes
	headerSize := binary.LittleEndian.Uint32(data[0:4])
	if headerSize < 48 || headerSize > 128 {
		return nil, fmt.Errorf("unexpected header size: %d", headerSize)
	}

	var entries []shimcacheEntry
	offset := int(headerSize) // Skip header

	for offset+12 < len(data) {
		entrySig := binary.LittleEndian.Uint32(data[offset : offset+4])
		if entrySig != shimcacheWin10Sig {
			break
		}

		entryStart := offset

		// Entry header: sig(4) + unknown(4) + data_size(4)
		dataSize := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
		dataStart := offset + 12
		nextEntry := dataStart + dataSize

		if nextEntry > len(data) {
			break
		}

		// Parse data block: path_len(2) + path + FILETIME(8)
		var path string
		var lastMod time.Time

		if dataStart+2 <= len(data) {
			pathLen := int(binary.LittleEndian.Uint16(data[dataStart : dataStart+2]))
			pathStart := dataStart + 2

			if pathStart+pathLen <= len(data) {
				path = decodeUTF16LEShim(data[pathStart : pathStart+pathLen])

				// FILETIME follows path
				ftStart := pathStart + pathLen
				if ftStart+8 <= len(data) {
					ft := binary.LittleEndian.Uint64(data[ftStart : ftStart+8])
					if ft > 0 {
						lastMod = filetimeToTime(int64(ft))
					}
				}
			}
		}

		entries = append(entries, shimcacheEntry{
			Path:         path,
			LastModified: lastMod,
			DataSize:     uint32(dataSize),
			DataOffset:   entryStart,
			EntrySize:    nextEntry - entryStart,
		})

		offset = nextEntry
	}

	return entries, nil
}

// parseShimcacheWin8 parses Windows 8/8.1 Shimcache format.
// Format: 4-byte signature (0x80) + entries with length-prefixed paths.
func parseShimcacheWin8(data []byte) ([]shimcacheEntry, error) {
	if len(data) < 128 {
		return nil, fmt.Errorf("data too small: %d bytes", len(data))
	}

	var entries []shimcacheEntry
	offset := 128 // Skip header

	for offset < len(data)-12 {
		if offset+4 > len(data) {
			break
		}

		// Path length in characters (UTF-16)
		pathLenChars := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		pathLenBytes := int(pathLenChars * 2)
		if pathLenBytes <= 0 || pathLenBytes > 2048 || offset+pathLenBytes > len(data) {
			break
		}

		path := decodeUTF16LEShim(data[offset : offset+pathLenBytes])
		offset += pathLenBytes

		// Last modified FILETIME
		var lastMod time.Time
		if offset+8 <= len(data) {
			ft := binary.LittleEndian.Uint64(data[offset : offset+8])
			if ft > 0 {
				lastMod = filetimeToTime(int64(ft))
			}
			offset += 8
		}

		// Data size + data
		if offset+4 > len(data) {
			break
		}
		dataSize := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		offset += int(dataSize)

		entries = append(entries, shimcacheEntry{
			Path:         path,
			LastModified: lastMod,
			DataSize:     dataSize,
		})
	}

	return entries, nil
}

// parseShimcache auto-detects format and parses shimcache data.
func parseShimcache(data []byte) ([]shimcacheEntry, string, error) {
	if len(data) < 4 {
		return nil, "", fmt.Errorf("data too small")
	}

	headerVal := binary.LittleEndian.Uint32(data[0:4])

	// Windows 10/11: header starts with header size (typically 0x34 = 52)
	// Check if entries at offset headerVal start with "10ts" signature
	if headerVal >= 48 && headerVal <= 128 && int(headerVal)+4 <= len(data) {
		entrySig := binary.LittleEndian.Uint32(data[headerVal : headerVal+4])
		if entrySig == shimcacheWin10Sig {
			entries, err := parseShimcacheWin10(data)
			return entries, "Windows 10/11", err
		}
	}

	// Windows 8/8.1: header starts with 0x80
	if headerVal == 0x80 {
		entries, err := parseShimcacheWin8(data)
		return entries, "Windows 8/8.1", err
	}

	// Fallback: try Windows 10 format
	entries, err := parseShimcacheWin10(data)
	if err == nil && len(entries) > 0 {
		return entries, "Windows 10/11 (variant)", nil
	}

	return nil, "", fmt.Errorf("unsupported Shimcache format (header: 0x%08X, size: %d bytes)", headerVal, len(data))
}

// rebuildShimcacheWin10 rebuilds the binary Shimcache data keeping only specified entries.
func rebuildShimcacheWin10(header []byte, keepEntries []shimcacheEntry, originalData []byte) []byte {
	// Start with the header
	result := make([]byte, len(header))
	copy(result, header)

	// Append each kept entry's raw bytes from the original data
	for _, e := range keepEntries {
		if e.DataOffset+e.EntrySize > len(originalData) {
			return nil
		}
		result = append(result, originalData[e.DataOffset:e.DataOffset+e.EntrySize]...)
	}

	return result
}

// --- UTF-16 decoding (from prefetch.go) ---

// decodeUTF16 decodes a UTF-16LE byte slice to a Go string,
// stopping at the first null terminator.
func decodeUTF16(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Convert bytes to uint16 slice
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}

	// Find null terminator
	for i, v := range u16s {
		if v == 0 {
			u16s = u16s[:i]
			break
		}
	}

	return string(utf16.Decode(u16s))
}

// --- USN Journal helpers (from usnjrnl.go) ---

// USN reason flags
const (
	usnReasonDataOverwrite       = 0x00000001
	usnReasonDataExtend          = 0x00000002
	usnReasonDataTruncation      = 0x00000004
	usnReasonNamedDataOverwrite  = 0x00000010
	usnReasonNamedDataExtend     = 0x00000020
	usnReasonNamedDataTruncation = 0x00000040
	usnReasonFileCreate          = 0x00000100
	usnReasonFileDelete          = 0x00000200
	usnReasonSecurityChange      = 0x00000800
	usnReasonRenameOldName       = 0x00001000
	usnReasonRenameNewName       = 0x00002000
	usnReasonBasicInfoChange     = 0x00008000
	usnReasonClose               = 0x80000000
)

// usnReasonString converts a USN reason bitmask to a human-readable string.
func usnReasonString(reason uint32) string {
	var parts []string
	if reason&usnReasonFileCreate != 0 {
		parts = append(parts, "Create")
	}
	if reason&usnReasonFileDelete != 0 {
		parts = append(parts, "Delete")
	}
	if reason&(usnReasonDataOverwrite|usnReasonDataExtend|usnReasonDataTruncation) != 0 {
		parts = append(parts, "DataChange")
	}
	if reason&(usnReasonRenameOldName|usnReasonRenameNewName) != 0 {
		parts = append(parts, "Rename")
	}
	if reason&usnReasonSecurityChange != 0 {
		parts = append(parts, "SecurityChange")
	}
	if reason&usnReasonBasicInfoChange != 0 {
		parts = append(parts, "InfoChange")
	}
	if reason&usnReasonClose != 0 {
		parts = append(parts, "Close")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08X", reason)
	}
	return strings.Join(parts, "|")
}
