//go:build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

const (
	fileAttrReadOnly    = 0x1
	fileAttrHidden      = 0x2
	fileAttrSystem      = 0x4
	fileAttrArchive     = 0x20
	fileAttrNormal      = 0x80
	fileAttrNotIndexed  = 0x2000
	fileAttrNoScrubData = 0x20000
)

var (
	procGetFileAttributesW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFileAttributesW")
	procSetFileAttributesW = syscall.NewLazyDLL("kernel32.dll").NewProc("SetFileAttributesW")
)

type winAttrDef struct {
	name string
	flag uint32
}

var winAttrDefs = []winAttrDef{
	{"readonly", fileAttrReadOnly},
	{"hidden", fileAttrHidden},
	{"system", fileAttrSystem},
	{"archive", fileAttrArchive},
	{"not_indexed", fileAttrNotIndexed},
}

func getFileAttrs(path string) structs.CommandResult {
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	ret, _, err := procGetFileAttributesW.Call(uintptr(unsafe.Pointer(pathPtr)))
	if ret == 0xFFFFFFFF {
		return errorf("Error getting attributes: %v", err)
	}

	attrs := uint32(ret)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] File attributes for: %s\n", path))
	sb.WriteString(fmt.Sprintf("    Raw value: 0x%08X\n", attrs))
	sb.WriteString("    Flags:\n")

	found := false
	for _, def := range winAttrDefs {
		if attrs&def.flag != 0 {
			sb.WriteString(fmt.Sprintf("      [+] %s\n", def.name))
			found = true
		}
	}
	if !found {
		sb.WriteString("      (none / normal)\n")
	}

	return successResult(sb.String())
}

func setFileAttrs(path string, attrsStr string) structs.CommandResult {
	add, remove, err := parseAttrChanges(attrsStr)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Get current attributes
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	ret, _, callErr := procGetFileAttributesW.Call(uintptr(unsafe.Pointer(pathPtr)))
	if ret == 0xFFFFFFFF {
		return errorf("Error getting current attributes: %v", callErr)
	}

	attrs := uint32(ret)

	// Apply changes
	var changed []string
	for _, def := range winAttrDefs {
		if attrContains(add, def.name) {
			if attrs&def.flag == 0 {
				attrs |= def.flag
				changed = append(changed, "+"+def.name)
			}
		}
		if attrContains(remove, def.name) {
			if attrs&def.flag != 0 {
				attrs &^= def.flag
				changed = append(changed, "-"+def.name)
			}
		}
	}

	if len(changed) == 0 {
		return successf("[*] No attribute changes needed for %s", path)
	}

	// If all attributes cleared, set NORMAL
	if attrs == 0 {
		attrs = fileAttrNormal
	}

	ret, _, callErr = procSetFileAttributesW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(attrs),
	)
	if ret == 0 {
		return errorf("Error setting attributes: %v", callErr)
	}

	return successf("[+] Updated attributes on %s: %s", path, strings.Join(changed, ", "))
}
