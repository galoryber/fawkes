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

// snapshotProcess holds the fast, snapshot-based process data that never hangs.
type snapshotProcess struct {
	pid  int32
	ppid int32
	name string
}

// getProcessList enumerates processes using a single CreateToolhelp32Snapshot
// call, avoiding gopsutil which can hang the entire Go runtime on Windows.
// Process names and PIDs are read from the snapshot (fast, never hangs).
// Username and exe path are queried per-process with a timeout.
func getProcessList(args PsArgs) ([]ProcessInfo, error) {
	// Take a single process snapshot — this is fast and atomic
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	// Read all processes from the snapshot
	var snapProcs []snapshotProcess
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(snap, &pe32)
	if err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	for {
		name := syscall.UTF16ToString(pe32.ExeFile[:])
		snapProcs = append(snapProcs, snapshotProcess{
			pid:  int32(pe32.ProcessID),
			ppid: int32(pe32.ParentProcessID),
			name: name,
		})
		err = windows.Process32Next(snap, &pe32)
		if err != nil {
			break
		}
	}

	// Now filter and enrich each process
	filterLower := strings.ToLower(args.Filter)
	userFilterLower := strings.ToLower(args.User)
	var processes []ProcessInfo

	for _, sp := range snapProcs {
		if args.PID > 0 && sp.pid != args.PID {
			continue
		}
		if args.Filter != "" && !strings.Contains(strings.ToLower(sp.name), filterLower) {
			continue
		}
		if args.PPID > 0 && sp.ppid != args.PPID {
			continue
		}

		// Query expensive attributes with a timeout
		username, exePath := queryWinProcessAttrs(uint32(sp.pid))

		if args.User != "" && !strings.Contains(strings.ToLower(username), userFilterLower) {
			continue
		}

		// Determine architecture from exe path
		arch := "amd64"
		exeLower := strings.ToLower(exePath)
		if strings.Contains(exeLower, "syswow64") {
			arch = "x86"
		} else if strings.Contains(exeLower, "system32") {
			arch = "x64"
		}

		processes = append(processes, ProcessInfo{
			PID:     sp.pid,
			PPID:    sp.ppid,
			Name:    sp.name,
			Arch:    arch,
			User:    username,
			BinPath: exePath,
		})
	}

	return processes, nil
}

// queryWinProcessAttrs queries a process's username and exe path with a timeout.
// Returns empty strings if the query times out or fails (protected processes).
func queryWinProcessAttrs(pid uint32) (username, exePath string) {
	// System idle (0) and System (4) can't be queried
	if pid == 0 || pid == 4 {
		return "", ""
	}

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
