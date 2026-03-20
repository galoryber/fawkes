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
			var username, exePath string

			// Only query per-process handles when needed (avoids Defender RADAR)
			if needPerProcess && pid > 4 {
				username, exePath = queryWinProcessAttrs(uint32(pid))
				if args.User != "" && !strings.Contains(strings.ToLower(username), userFilterLower) {
					goto next
				}
			}

			arch := "amd64"
			if exePath != "" {
				exeLower := strings.ToLower(exePath)
				if strings.Contains(exeLower, "syswow64") {
					arch = "x86"
				} else if strings.Contains(exeLower, "system32") {
					arch = "x64"
				}
			}

			processes = append(processes, ProcessInfo{
				PID:     pid,
				PPID:    ppid,
				Name:    name,
				Arch:    arch,
				User:    username,
				BinPath: exePath,
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

// queryWinProcessAttrs queries a process's username and exe path with a timeout.
// Returns empty strings if the query times out or fails (protected processes).
func queryWinProcessAttrs(pid uint32) (username, exePath string) {
	type result struct {
		username, exePath string
	}
	ch := make(chan result, 1)
	go func() {
		u := getProcessUsername(pid)
		e := getProcessExePath(pid)
		ch <- result{u, e}
	}()
	select {
	case r := <-ch:
		return r.username, r.exePath
	case <-time.After(perProcessTimeout):
		return "", ""
	}
}

// getProcessUsername opens a process token and looks up the owner's account name.
func getProcessUsername(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
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

// getProcessExePath retrieves the full executable path of a process.
func getProcessExePath(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}
