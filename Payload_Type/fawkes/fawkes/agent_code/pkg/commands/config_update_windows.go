//go:build windows
// +build windows

package commands

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func launchAndReplace(binaryPath string) error {
	argv, err := syscall.UTF16PtrFromString(binaryPath)
	if err != nil {
		return err
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)

	err = windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		false,
		flags,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return err
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	go func() {
		os.Exit(0)
	}()

	return nil
}
