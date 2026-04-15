//go:build windows
// +build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API procedures for process helpers
var (
	kernel32DLL                  = windows.NewLazySystemDLL("kernel32.dll")
	advapi32DLL                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateToolhelp32Snapshot = kernel32DLL.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = kernel32DLL.NewProc("Thread32First")
	procThread32Next             = kernel32DLL.NewProc("Thread32Next")
	procProcess32FirstW          = kernel32DLL.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32DLL.NewProc("Process32NextW")
	procIsWow64Process           = kernel32DLL.NewProc("IsWow64Process")
	procGetSidSubAuthorityCount  = advapi32DLL.NewProc("GetSidSubAuthorityCount")
	procGetSidSubAuthority       = advapi32DLL.NewProc("GetSidSubAuthority")
)

// Integrity level constants
const (
	SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
	SECURITY_MANDATORY_LOW_RID       = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID    = 0x00002000
	SECURITY_MANDATORY_HIGH_RID      = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID    = 0x00004000
)

// getProcessNames returns a map of process names by PID using toolhelp32 snapshot
func getProcessNames() map[uint32]string {
	names := make(map[uint32]string)

	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return names
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry PROCESSENTRY32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return names
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		names[entry.ProcessID] = name

		ret, _, err = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			break
		}
	}

	return names
}

// getProcessArch determines if a process is 32-bit or 64-bit
func getProcessArch(pid uint32) string {
	// Default to x64 on 64-bit systems
	arch := "x64"

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return arch
	}
	defer windows.CloseHandle(handle)

	var isWow64 bool
	ret, _, _ := procIsWow64Process.Call(uintptr(handle), uintptr(unsafe.Pointer(&isWow64)))
	if ret != 0 && isWow64 {
		arch = "x86"
	}

	return arch
}

// getProcessOwner returns the owner of a process in DOMAIN\user format
func getProcessOwner(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "Access Denied"
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Access Denied"
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "Unknown"
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "Unknown"
	}

	return fmt.Sprintf("%s\\%s", domain, account)
}

// getProcessIntegrity returns the integrity level of a process
func getProcessIntegrity(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "Access Denied"
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Access Denied"
	}
	defer token.Close()

	// Check for SYSTEM first
	tokenUser, err := token.GetTokenUser()
	if err == nil {
		systemSID, _ := windows.StringToSid("S-1-5-18")
		if tokenUser.User.Sid.Equals(systemSID) {
			return "System"
		}
	}

	// Get token integrity level
	var size uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return "Unknown"
	}

	buffer := make([]byte, size)
	err = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], size, &size)
	if err != nil {
		return "Unknown"
	}

	// Parse TOKEN_MANDATORY_LABEL
	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	sid := tml.Label.Sid

	// Get the RID (last subauthority) using advapi32 calls
	subAuthCountPtr, _, _ := procGetSidSubAuthorityCount.Call(uintptr(unsafe.Pointer(sid)))
	if subAuthCountPtr == 0 {
		return "Unknown"
	}
	subAuthCount := *(*uint8)(unsafe.Pointer(subAuthCountPtr))
	if subAuthCount == 0 {
		return "Unknown"
	}

	ridPtr, _, _ := procGetSidSubAuthority.Call(
		uintptr(unsafe.Pointer(sid)),
		uintptr(subAuthCount-1),
	)
	if ridPtr == 0 {
		return "Unknown"
	}
	rid := *(*uint32)(unsafe.Pointer(ridPtr))

	switch {
	case rid < SECURITY_MANDATORY_LOW_RID:
		return "Untrusted"
	case rid < SECURITY_MANDATORY_MEDIUM_RID:
		return "Low"
	case rid < SECURITY_MANDATORY_HIGH_RID:
		return "Medium"
	case rid < SECURITY_MANDATORY_SYSTEM_RID:
		return "High"
	default:
		return "System"
	}
}
