//go:build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// perProcessTimeout limits time spent querying per-process attributes (username,
// exe path) via Windows API calls that can hang on protected processes.
const perProcessTimeout = 2 * time.Second

// getProcessList enumerates processes using a single CreateToolhelp32Snapshot.
// By default, only PID/PPID/Name are returned from the snapshot (fast, atomic,
// does not trigger Windows Defender RADAR). Per-process handle queries (username,
// exe path) are only performed when a user filter is specified (Verbose mode)
// to avoid RADAR_PRE_LEAK_64 detection from mass OpenProcess calls.
func getProcessList(args PsArgs) ([]ProcessInfo, error) {
	// Take a single process snapshot — fast and atomic
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(snap, &pe32)
	if err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	filterLower := strings.ToLower(args.Filter)
	userFilterLower := strings.ToLower(args.User)
	needPerProcess := args.User != "" || args.Verbose
	var processes []ProcessInfo

	for {
		pid := int32(pe32.ProcessID)
		ppid := int32(pe32.ParentProcessID)
		name := syscall.UTF16ToString(pe32.ExeFile[:])

		// Apply fast filters from snapshot data
		if args.PID > 0 && pid != args.PID {
			goto next
		}
		if args.Filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			goto next
		}
		if args.PPID > 0 && ppid != args.PPID {
			goto next
		}

		{
			var attrs processAttrs

			// Only query per-process handles when needed (avoids Defender RADAR)
			if needPerProcess && pid > 4 {
				attrs = queryWinProcessAttrs(uint32(pid))
				if args.User != "" && !strings.Contains(strings.ToLower(attrs.username), userFilterLower) {
					goto next
				}
			}

			arch := "amd64"
			if attrs.exePath != "" {
				exeLower := strings.ToLower(attrs.exePath)
				if strings.Contains(exeLower, "syswow64") {
					arch = "x86"
				} else if strings.Contains(exeLower, "system32") {
					arch = "x64"
				}
			}

			processes = append(processes, ProcessInfo{
				PID:            pid,
				PPID:           ppid,
				Name:           name,
				Arch:           arch,
				User:           attrs.username,
				BinPath:        attrs.exePath,
				IntegrityLevel: attrs.integrityLevel,
				StartTime:      attrs.startTime,
			})
		}

	next:
		err = windows.Process32Next(snap, &pe32)
		if err != nil {
			break
		}
	}

	return processes, nil
}

// processAttrs holds per-process attributes queried via handle operations.
type processAttrs struct {
	username       string
	exePath        string
	integrityLevel int
	startTime      int64
}

// queryWinProcessAttrs queries a process's username, exe path, integrity level,
// and start time with a timeout. Returns zero values on timeout or failure.
func queryWinProcessAttrs(pid uint32) processAttrs {
	ch := make(chan processAttrs, 1)
	go func() {
		var attrs processAttrs
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			ch <- attrs
			return
		}
		defer windows.CloseHandle(handle)

		attrs.username = getProcessUsernameFromHandle(handle)
		attrs.exePath = getProcessExePathFromHandle(handle)
		attrs.integrityLevel = getProcessIntegrityLevel(handle)
		attrs.startTime = getProcessStartTime(handle)
		ch <- attrs
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(perProcessTimeout):
		return processAttrs{}
	}
}

// getProcessUsernameFromHandle looks up the process owner from an open handle.
func getProcessUsernameFromHandle(handle windows.Handle) string {
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}

	if domain != "" {
		return domain + "\\" + account
	}
	return account
}

// getProcessExePathFromHandle retrieves the full executable path from an open handle.
func getProcessExePathFromHandle(handle windows.Handle) string {
	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// getProcessIntegrityLevel returns the integrity level (0-4) from an open handle.
// 0=untrusted, 1=low, 2=medium, 3=high, 4=system
func getProcessIntegrityLevel(handle windows.Handle) int {
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return 0
	}
	defer token.Close()

	// Get token integrity level
	var infoLen uint32
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &infoLen)
	if infoLen == 0 {
		return 0
	}
	buf := make([]byte, infoLen)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], infoLen, &infoLen); err != nil {
		return 0
	}

	til := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	if til.GroupCount == 0 {
		return 0
	}
	sid := til.Groups[0].Sid
	subAuthCount := int(sid.SubAuthorityCount())
	if subAuthCount == 0 {
		return 0
	}
	rid := sid.SubAuthority(uint32(subAuthCount - 1))

	switch {
	case rid >= 0x4000: // SYSTEM
		return 4
	case rid >= 0x3000: // HIGH
		return 3
	case rid >= 0x2000: // MEDIUM
		return 2
	case rid >= 0x1000: // LOW
		return 1
	default: // UNTRUSTED
		return 0
	}
}

// getProcessStartTime returns the process creation time as Unix epoch seconds.
func getProcessStartTime(handle windows.Handle) int64 {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	t := creation.Nanoseconds()/1e9 - 11644473600 // Windows FILETIME epoch to Unix epoch
	if t < 0 {
		return 0
	}
	return t
}
