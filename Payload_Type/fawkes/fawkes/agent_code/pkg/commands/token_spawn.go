//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SpawnResult holds information about a process spawned with a token.
type SpawnResult struct {
	PID      uint32
	Identity string
}

// spawnWithToken creates a new detached process using CreateProcessWithTokenW.
// The process runs under the security context of the provided token.
// Unlike runWithToken(), this does not capture output — the spawned process
// runs independently (fire-and-forget).
//
// CreateProcessWithTokenW requires SE_IMPERSONATE_NAME privilege (admin users).
// For SYSTEM, CreateProcessAsUserW would also work but SE_IMPERSONATE is
// more broadly available.
func spawnWithToken(token windows.Token, cmdLine string) (*SpawnResult, error) {
	if token == 0 {
		return nil, fmt.Errorf("no token provided")
	}

	if cmdLine == "" {
		return nil, fmt.Errorf("no command line provided")
	}

	// Get the identity of the token for output
	identity, _ := GetTokenUserInfo(token)

	cmdUTF16, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, fmt.Errorf("invalid command line: %w", err)
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = syscall.SW_HIDE

	var pi syscall.ProcessInformation

	// CreateProcessWithTokenW: create process under the token's security context.
	// dwLogonFlags = LOGON_WITH_PROFILE (1) loads the user's profile.
	ret, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(token),
		1, // LOGON_WITH_PROFILE
		0, // lpApplicationName (nil — use command line)
		uintptr(unsafe.Pointer(cmdUTF16)),
		uintptr(CREATE_NO_WINDOW),
		0, // lpEnvironment (nil — inherit)
		0, // lpCurrentDirectory (nil — inherit)
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CreateProcessWithTokenW failed: %w", callErr)
	}

	pid := pi.ProcessId

	// Close handles — the process runs independently
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)

	return &SpawnResult{
		PID:      pid,
		Identity: identity,
	}, nil
}
