package agentfunctions

import (
	"encoding/binary"
	"fmt"

	"github.com/MythicAgents/merlin/Payload_Type/merlin/container/pkg/srdi"
)

// convertDllToShellcode uses Merlin's Go-based sRDI to convert a DLL to position-independent shellcode
func convertDllToShellcode(dllBytes []byte, functionName string, clearHeader bool) ([]byte, error) {
	// Use Merlin's Go sRDI implementation - same as working Merlin agent
	shellcode := srdi.DLLToReflectiveShellcode(dllBytes, functionName, clearHeader, "")

	if len(shellcode) == 0 {
		return nil, fmt.Errorf("sRDI conversion produced empty shellcode")
	}

	return shellcode, nil
}

// is64BitDLL checks if the DLL is 64-bit by examining the PE header
func is64BitDLL(dllBytes []byte) bool {
	if len(dllBytes) < 64 {
		return false
	}

	// Get offset to PE header from bytes 60-64
	headerOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
	if int(headerOffset)+6 > len(dllBytes) {
		return false
	}

	// Read machine type from PE header
	machine := binary.LittleEndian.Uint16(dllBytes[headerOffset+4 : headerOffset+6])

	// 0x8664 = AMD64, 0x0200 = IA64
	return machine == 0x8664 || machine == 0x0200
}
