//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// HandlesCommand enumerates open handles for a process
type HandlesCommand struct{}

func (c *HandlesCommand) Name() string        { return "handles" }
func (c *HandlesCommand) Description() string { return "Enumerate open handles in a process (T1057)" }

type handlesArgs struct {
	PID       int    `json:"pid"`
	TypeName  string `json:"type"`
	MaxCount  int    `json:"max_count"`
	ShowNames bool   `json:"show_names"`
}

type handleInfo struct {
	Handle   uint16 `json:"handle"`
	TypeName string `json:"type"`
	Name     string `json:"name,omitempty"`
}

// Windows NT API constants
const (
	systemHandleInformation    = 16
	statusInfoLengthMismatch   = 0xC0000004
	statusBufferTooSmall       = 0xC0000023
	objectNameInformation      = 1
	objectTypeInformation      = 2
	processQueryLimitedInfo    = 0x1000
	processDupHandle           = 0x0040
	duplicateCloseSource       = 0x00000001
	duplicateSameAccess        = 0x00000002
	duplicateSameAttributes    = 0x00000004
)

// SYSTEM_HANDLE_TABLE_ENTRY_INFO - per-handle entry in SystemHandleInformation
type systemHandleEntry struct {
	OwnerPID       uint32
	ObjectTypeIdx  uint8
	HandleAttr     uint8
	HandleValue    uint16
	ObjectPtr      uintptr
	GrantedAccess  uint32
}

var (
	ntdllForHandles           = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySysInfoHandles = ntdllForHandles.NewProc("NtQuerySystemInformation")
	procNtQueryObjHandles     = ntdllForHandles.NewProc("NtQueryObject")
	procNtDuplicateObjHandles = ntdllForHandles.NewProc("NtDuplicateObject")
)

func (c *HandlesCommand) Execute(task structs.Task) structs.CommandResult {
	var args handlesArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.PID <= 0 {
		return structs.CommandResult{
			Output:    "Error: pid is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.MaxCount <= 0 {
		args.MaxCount = 500
	}

	// Query all system handles
	entries, err := querySystemHandles()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying system handles: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Filter to target PID
	var pidEntries []systemHandleEntry
	for _, e := range entries {
		if e.OwnerPID == uint32(args.PID) {
			pidEntries = append(pidEntries, e)
		}
	}

	if len(pidEntries) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No handles found for PID %d (0 of %d system handles)", args.PID, len(entries)),
			Status:    "success",
			Completed: true,
		}
	}

	// Open target process to duplicate handles from
	procHandle, err := windows.OpenProcess(processQueryLimitedInfo|processDupHandle, false, uint32(args.PID))
	if err != nil {
		// Fall back to summary-only mode (no names)
		return formatHandleSummary(pidEntries, args, len(entries), nil)
	}
	defer windows.CloseHandle(procHandle)

	// Resolve handle types and optionally names
	var handles []handleInfo
	typeCounts := make(map[string]int)
	currentProcess, _ := windows.GetCurrentProcess()

	for i, entry := range pidEntries {
		if i >= args.MaxCount {
			break
		}

		hi := handleInfo{
			Handle: entry.HandleValue,
		}

		// Duplicate the handle into our process for querying
		var dupHandle windows.Handle
		ret, _, _ := procNtDuplicateObjHandles.Call(
			uintptr(procHandle),
			uintptr(entry.HandleValue),
			uintptr(currentProcess),
			uintptr(unsafe.Pointer(&dupHandle)),
			0,
			0,
			duplicateSameAccess,
		)

		if ret == 0 && dupHandle != 0 {
			// Query object type
			hi.TypeName = queryObjectType(dupHandle)

			// Query object name if requested and type is safe
			if args.ShowNames && isSafeToQueryName(hi.TypeName) {
				hi.Name = queryObjectName(dupHandle)
			}

			windows.CloseHandle(dupHandle)
		}

		if hi.TypeName == "" {
			hi.TypeName = fmt.Sprintf("Type_%d", entry.ObjectTypeIdx)
		}

		// Apply type filter
		if args.TypeName != "" && !strings.EqualFold(hi.TypeName, args.TypeName) {
			continue
		}

		typeCounts[hi.TypeName]++
		handles = append(handles, hi)
	}

	return formatHandleOutput(handles, typeCounts, args, len(pidEntries), len(entries))
}

func querySystemHandles() ([]systemHandleEntry, error) {
	// Start with a reasonable buffer, grow as needed
	bufSize := uint32(1024 * 1024) // 1MB initial
	for attempts := 0; attempts < 8; attempts++ {
		buf := make([]byte, bufSize)
		var retLen uint32
		ret, _, _ := procNtQuerySysInfoHandles.Call(
			uintptr(systemHandleInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&retLen)),
		)

		ntStatus := uint32(ret)
		if ntStatus == statusInfoLengthMismatch || ntStatus == statusBufferTooSmall {
			if retLen > bufSize {
				bufSize = retLen + 4096
			} else {
				bufSize *= 2
			}
			continue
		}

		if ntStatus != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation failed: 0x%X", ntStatus)
		}

		// Parse the SYSTEM_HANDLE_INFORMATION structure
		// First 4 bytes (on 32-bit) or 8 bytes (on 64-bit) = NumberOfHandles
		// On 64-bit Windows, the count is stored as a native-sized integer
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		entrySize := unsafe.Sizeof(systemHandleEntry{})

		// Validate count
		maxPossible := (bufSize - 8) / uint32(entrySize)
		if count > maxPossible {
			count = maxPossible
		}

		entries := make([]systemHandleEntry, count)
		// Entries start after the count field (pointer-sized on 64-bit)
		offset := unsafe.Sizeof(uintptr(0)) // 8 bytes on amd64
		for i := uint32(0); i < count; i++ {
			entries[i] = *(*systemHandleEntry)(unsafe.Pointer(
				uintptr(unsafe.Pointer(&buf[0])) + offset + uintptr(i)*entrySize,
			))
		}

		return entries, nil
	}

	return nil, fmt.Errorf("failed to query system handles after multiple attempts")
}

func queryObjectType(handle windows.Handle) string {
	buf := make([]byte, 1024)
	var retLen uint32
	ret, _, _ := procNtQueryObjHandles.Call(
		uintptr(handle),
		uintptr(objectTypeInformation),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret != 0 {
		return ""
	}

	return parseUnicodeStringFromBuffer(buf, retLen)
}

// parseUnicodeStringFromBuffer extracts the string from a UNICODE_STRING at the start of buf.
// The Buffer pointer in the UNICODE_STRING points to the actual UTF-16 data within the buffer.
func parseUnicodeStringFromBuffer(buf []byte, retLen uint32) string {
	if retLen < 16 { // Need at least UNICODE_STRING header (16 bytes on amd64)
		return ""
	}

	us := (*unicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == 0 {
		return ""
	}

	// The Buffer pointer is absolute — compute offset within our buf
	bufStart := uintptr(unsafe.Pointer(&buf[0]))
	bufEnd := bufStart + uintptr(len(buf))

	if us.Buffer < bufStart || us.Buffer >= bufEnd {
		return "" // Buffer points outside our allocation
	}

	charCount := us.Length / 2
	available := (bufEnd - us.Buffer) / 2
	if uintptr(charCount) > available {
		charCount = uint16(available)
	}

	nameSlice := unsafe.Slice((*uint16)(unsafe.Pointer(us.Buffer)), charCount)
	return syscall.UTF16ToString(nameSlice)
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             uint32 // padding on amd64
	Buffer        uintptr
}

func queryObjectName(handle windows.Handle) string {
	buf := make([]byte, 2048)
	var retLen uint32
	ret, _, _ := procNtQueryObjHandles.Call(
		uintptr(handle),
		uintptr(objectNameInformation),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret != 0 {
		return ""
	}

	return parseUnicodeStringFromBuffer(buf, retLen)
}

// isSafeToQueryName returns true for handle types where NtQueryObject won't hang
func isSafeToQueryName(typeName string) bool {
	// NtQueryObject can deadlock on ALPC Port, WaitCompletionPacket, and some pipe handles
	unsafeTypes := map[string]bool{
		"ALPC Port":             true,
		"WaitCompletionPacket":  true,
		"TpWorkerFactory":       true,
		"IRTimer":               true,
		"IoCompletion":          true,
		"IoCompletionReserve":   true,
	}
	return !unsafeTypes[typeName]
}

func formatHandleOutput(handles []handleInfo, typeCounts map[string]int, args handlesArgs, pidTotal, sysTotal int) structs.CommandResult {
	type typeCount struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	var summary []typeCount
	for name, count := range typeCounts {
		summary = append(summary, typeCount{name, count})
	}
	sort.Slice(summary, func(i, j int) bool { return summary[i].Count > summary[j].Count })

	type handlesOutput struct {
		PID      int          `json:"pid"`
		Shown    int          `json:"shown"`
		Total    int          `json:"total"`
		System   int          `json:"system"`
		Summary  []typeCount  `json:"summary"`
		Handles  []handleInfo `json:"handles"`
	}

	out := handlesOutput{
		PID:     args.PID,
		Shown:   len(handles),
		Total:   pidTotal,
		System:  sysTotal,
		Summary: summary,
		Handles: handles,
	}

	jsonBytes, err := json.Marshal(out)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshalling handle data: %v", err),
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

func formatHandleSummary(entries []systemHandleEntry, args handlesArgs, sysTotal int, _ error) structs.CommandResult {
	// Count by type index
	typeCounts := make(map[uint8]int)
	for _, e := range entries {
		typeCounts[e.ObjectTypeIdx]++
	}

	type indexCount struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	var summary []indexCount
	for idx, count := range typeCounts {
		summary = append(summary, indexCount{fmt.Sprintf("Type_%d", idx), count})
	}
	sort.Slice(summary, func(i, j int) bool { return summary[i].Count > summary[j].Count })

	type summaryOutput struct {
		PID     int          `json:"pid"`
		Total   int          `json:"total"`
		System  int          `json:"system"`
		Note    string       `json:"note"`
		Summary []indexCount `json:"summary"`
	}

	out := summaryOutput{
		PID:     args.PID,
		Total:   len(entries),
		System:  sysTotal,
		Note:    "Could not open process — showing count only",
		Summary: summary,
	}

	jsonBytes, err := json.Marshal(out)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshalling handle data: %v", err),
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
