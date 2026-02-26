//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type WindowsEnumCommand struct{}

func (c *WindowsEnumCommand) Name() string {
	return "windows"
}

func (c *WindowsEnumCommand) Description() string {
	return "Enumerate visible application windows (T1010)"
}

type weArgs struct {
	Action string `json:"action"`
	Filter string `json:"filter"`
	All    bool   `json:"all"`
}

var (
	user32WE          = windows.NewLazySystemDLL("user32.dll")
	weEnumWindowsProc = user32WE.NewProc("EnumWindows")
	weGetTextW        = user32WE.NewProc("GetWindowTextW")
	weGetTextLenW     = user32WE.NewProc("GetWindowTextLengthW")
	weIsVisible       = user32WE.NewProc("IsWindowVisible")
	weGetTIDPID       = user32WE.NewProc("GetWindowThreadProcessId")
	weGetClassW       = user32WE.NewProc("GetClassNameW")
)

type weEntry struct {
	HWND      uintptr
	PID       uint32
	TID       uint32
	Title     string
	ClassName string
	Visible   bool
	Process   string
}

func (c *WindowsEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args weArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list", "search":
		return weDoEnum(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use: list, search)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func weDoEnum(args weArgs) structs.CommandResult {
	var entries []weEntry

	cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		visible, _, _ := weIsVisible.Call(hwnd)
		isVisible := visible != 0

		if !args.All && !isVisible {
			return 1
		}

		titleLen, _, _ := weGetTextLenW.Call(hwnd)
		title := ""
		if titleLen > 0 {
			buf := make([]uint16, titleLen+1)
			weGetTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(titleLen+1))
			title = syscall.UTF16ToString(buf)
		}

		if title == "" && !args.All {
			return 1
		}

		var pid uint32
		tid, _, _ := weGetTIDPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))

		classBuf := make([]uint16, 256)
		weGetClassW.Call(hwnd, uintptr(unsafe.Pointer(&classBuf[0])), 256)
		className := syscall.UTF16ToString(classBuf)

		procName := ""
		if pid > 0 {
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			if err == nil {
				var buf [260]uint16
				size := uint32(260)
				err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
				if err == nil {
					full := syscall.UTF16ToString(buf[:size])
					parts := strings.Split(full, "\\")
					procName = parts[len(parts)-1]
				}
				windows.CloseHandle(handle)
			}
		}

		entries = append(entries, weEntry{
			HWND:      hwnd,
			PID:       pid,
			TID:       uint32(tid),
			Title:     title,
			ClassName: className,
			Visible:   isVisible,
			Process:   procName,
		})

		return 1
	})

	ret, _, _ := weEnumWindowsProc.Call(cb, 0)
	if ret == 0 {
		return structs.CommandResult{
			Output:    "EnumWindows failed",
			Status:    "error",
			Completed: true,
		}
	}

	// Apply search filter
	if args.Action == "search" && args.Filter != "" {
		filter := strings.ToLower(args.Filter)
		var filtered []weEntry
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Title), filter) ||
				strings.Contains(strings.ToLower(e.Process), filter) ||
				strings.Contains(strings.ToLower(e.ClassName), filter) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	var sb strings.Builder
	sb.WriteString("[*] Application Window Discovery (T1010)\n")

	if args.Action == "search" && args.Filter != "" {
		sb.WriteString(fmt.Sprintf("[*] Filter: %q\n", args.Filter))
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d windows\n\n", len(entries)))

	if len(entries) > 0 {
		sb.WriteString(fmt.Sprintf("%-8s %-6s %-25s %-30s %s\n",
			"HWND", "PID", "Process", "Class", "Title"))
		sb.WriteString(strings.Repeat("-", 120) + "\n")

		for _, e := range entries {
			vis := ""
			if !e.Visible {
				vis = " [hidden]"
			}
			title := e.Title
			if len(title) > 50 {
				title = title[:47] + "..."
			}
			sb.WriteString(fmt.Sprintf("0x%-6X %-6d %-25s %-30s %s%s\n",
				e.HWND, e.PID, wetrunc(e.Process, 25), wetrunc(e.ClassName, 30), title, vis))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func wetrunc(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}
