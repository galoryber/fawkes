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
	"time"
	"unicode/utf16"
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

// Prefetch file header (versions 17/23/26/30)
type prefetchHeader struct {
	Version       uint32
	Signature     uint32 // "SCCA"
	FileSize      uint32
	ExecutableName [60]byte
	PrefetchHash  uint32
}

// Parsed prefetch entry
type prefetchEntry struct {
	FileName     string
	ExeName      string
	Hash         uint32
	RunCount     uint32
	LastRunTime  time.Time
	LastRunTimes []time.Time
	FileSize     int64
	ModTime      time.Time
}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'list', 'parse', 'delete', or 'clear')", params.Action),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read Prefetch directory: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
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

func prefetchParse(name string) structs.CommandResult {
	if name == "" {
		return structs.CommandResult{
			Output:    "Name required — specify an executable name (e.g., 'CMD.EXE') or prefetch filename",
			Status:    "error",
			Completed: true,
		}
	}

	dir := getPrefetchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read Prefetch directory: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("No prefetch files matching '%s'", name),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    "Name required — specify an executable name to delete matching prefetch files",
			Status:    "error",
			Completed: true,
		}
	}

	dir := getPrefetchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read Prefetch directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var deleted, failed []string
	upperName := strings.ToUpper(name)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}
		if strings.Contains(strings.ToUpper(entry.Name()), upperName) {
			path := filepath.Join(dir, entry.Name())
			if err := os.Remove(path); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", entry.Name(), err))
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read Prefetch directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	deleted := 0
	failed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.Remove(path); err != nil {
			failed++
		} else {
			deleted++
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Prefetch cleared: %d files deleted, %d failed\n  Directory: %s", deleted, failed, dir),
		Status:    "success",
		Completed: true,
	}
}

// parsePrefetchFile reads and parses a Windows Prefetch file
// Supports versions 17 (XP), 23 (Vista/7), 26 (8.1), 30 (10/11)
func parsePrefetchFile(path string) (*prefetchEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Windows 10+ prefetch files are MAM compressed
	// Check for MAM signature (0x44, 0x41, 0x4D, 0x04 = "MAM\x04")
	if len(data) >= 8 && data[0] == 0x4D && data[1] == 0x41 && data[2] == 0x4D {
		decompressed, err := decompressMAM(data)
		if err != nil {
			return nil, fmt.Errorf("MAM decompress: %v", err)
		}
		data = decompressed
	}

	if len(data) < 84 {
		return nil, fmt.Errorf("file too small (%d bytes)", len(data))
	}

	// Parse header
	version := binary.LittleEndian.Uint32(data[0:4])
	signature := binary.LittleEndian.Uint32(data[4:8])

	if signature != 0x41434353 { // "SCCA"
		return nil, fmt.Errorf("invalid signature: 0x%08X", signature)
	}

	// Extract executable name (UTF-16LE, 60 bytes at offset 16)
	exeName := decodeUTF16(data[16:76])

	// Hash at offset 76
	hash := binary.LittleEndian.Uint32(data[76:80])

	entry := &prefetchEntry{
		ExeName: exeName,
		Hash:    hash,
	}

	// Version-specific parsing
	switch version {
	case 17: // Windows XP
		if len(data) >= 100 {
			entry.RunCount = binary.LittleEndian.Uint32(data[90:94])
			entry.LastRunTime = filetimeToTime(int64(binary.LittleEndian.Uint64(data[78:86])))
		}
	case 23: // Windows Vista/7
		if len(data) >= 160 {
			entry.RunCount = binary.LittleEndian.Uint32(data[152:156])
			entry.LastRunTime = filetimeToTime(int64(binary.LittleEndian.Uint64(data[128:136])))
		}
	case 26: // Windows 8.1
		if len(data) >= 224 {
			entry.RunCount = binary.LittleEndian.Uint32(data[208:212])
			// 8 last run times starting at offset 128
			for i := 0; i < 8; i++ {
				off := 128 + i*8
				if off+8 <= len(data) {
					t := filetimeToTime(int64(binary.LittleEndian.Uint64(data[off : off+8])))
					if !t.IsZero() && t.Year() > 2000 {
						entry.LastRunTimes = append(entry.LastRunTimes, t)
					}
				}
			}
			if len(entry.LastRunTimes) > 0 {
				entry.LastRunTime = entry.LastRunTimes[0]
			}
		}
	case 30, 31: // Windows 10/11
		if len(data) >= 224 {
			entry.RunCount = binary.LittleEndian.Uint32(data[208:212])
			// 8 last run times starting at offset 128
			for i := 0; i < 8; i++ {
				off := 128 + i*8
				if off+8 <= len(data) {
					t := filetimeToTime(int64(binary.LittleEndian.Uint64(data[off : off+8])))
					if !t.IsZero() && t.Year() > 2000 {
						entry.LastRunTimes = append(entry.LastRunTimes, t)
					}
				}
			}
			if len(entry.LastRunTimes) > 0 {
				entry.LastRunTime = entry.LastRunTimes[0]
			}
		}
	}

	return entry, nil
}

var (
	ntdllPF                       = windows.NewLazySystemDLL("ntdll.dll")
	procRtlDecompressBufferEx     = ntdllPF.NewProc("RtlDecompressBufferEx")
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

