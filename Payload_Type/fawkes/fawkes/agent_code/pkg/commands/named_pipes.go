//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type NamedPipesCommand struct{}

func (c *NamedPipesCommand) Name() string {
	return "named-pipes"
}

func (c *NamedPipesCommand) Description() string {
	return "List named pipes on the system"
}

type namedPipesArgs struct {
	Filter string `json:"filter"`
}

// Windows constants for pipe enumeration
var (
	kernel32NP          = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstFileW  = kernel32NP.NewProc("FindFirstFileW")
	procFindNextFileW   = kernel32NP.NewProc("FindNextFileW")
	procFindClose       = kernel32NP.NewProc("FindClose")
)

// WIN32_FIND_DATAW structure (592 bytes)
type win32FindDataW struct {
	FileAttributes    uint32
	CreationTime      windows.Filetime
	LastAccessTime    windows.Filetime
	LastWriteTime     windows.Filetime
	FileSizeHigh      uint32
	FileSizeLow       uint32
	Reserved0         uint32
	Reserved1         uint32
	FileName          [260]uint16
	AlternateFileName [14]uint16
}

func (c *NamedPipesCommand) Execute(task structs.Task) structs.CommandResult {
	var args namedPipesArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	pipes, err := enumerateNamedPipes()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate named pipes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Filter if specified
	if args.Filter != "" {
		filterLower := strings.ToLower(args.Filter)
		var filtered []string
		for _, p := range pipes {
			if strings.Contains(strings.ToLower(p), filterLower) {
				filtered = append(filtered, p)
			}
		}
		pipes = filtered
	}

	sort.Strings(pipes)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Named pipes: %d\n", len(pipes)))
	if args.Filter != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s\n", args.Filter))
	}
	sb.WriteString("\n")

	for _, p := range pipes {
		sb.WriteString(fmt.Sprintf("  \\\\.\\pipe\\%s\n", p))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// enumerateNamedPipes lists all named pipes using FindFirstFile/FindNextFile
func enumerateNamedPipes() ([]string, error) {
	searchPath, err := windows.UTF16PtrFromString(`\\.\pipe\*`)
	if err != nil {
		return nil, err
	}

	var fd win32FindDataW
	handle, _, callErr := procFindFirstFileW.Call(
		uintptr(unsafe.Pointer(searchPath)),
		uintptr(unsafe.Pointer(&fd)),
	)

	if handle == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("FindFirstFile: %v", callErr)
	}
	defer procFindClose.Call(handle)

	var pipes []string
	for {
		name := windows.UTF16ToString(fd.FileName[:])
		if name != "." && name != ".." {
			pipes = append(pipes, name)
		}

		ret, _, _ := procFindNextFileW.Call(handle, uintptr(unsafe.Pointer(&fd)))
		if ret == 0 {
			break
		}
	}

	return pipes, nil
}
