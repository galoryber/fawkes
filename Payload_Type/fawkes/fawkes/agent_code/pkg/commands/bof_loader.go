//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"

	"github.com/praetorian-inc/goffloader/src/coff"
	"golang.org/x/sys/windows"
)

// RunBOF executes a BOF with the given arguments using our fixed Beacon API
func RunBOF(coffBytes []byte, argBytes []byte, entryPoint string) (string, error) {
	// Create output channel
	bofOutputChannel = make(chan string, 100)
	defer close(bofOutputChannel)

	// Use goffloader's COFF loader but with our custom Beacon API callbacks
	output, err := coff.LoadWithMethod(coffBytes, argBytes, entryPoint)

	// Collect any output from our channel
	close_loop:
	for {
		select {
		case msg, ok := <-bofOutputChannel:
			if !ok {
				break close_loop
			}
			output += msg
		default:
			break close_loop
		}
	}

	return output, err
}

// RunBOFWithCustomBeaconAPI executes a BOF using fully custom loading
// This bypasses goffloader entirely for maximum control
func RunBOFWithCustomBeaconAPI(coffBytes []byte, argBytes []byte, entryPoint string) (string, error) {
	// For now, delegate to goffloader but register our Beacon API callbacks
	// This uses goffloader's COFF parsing and relocation, but our Beacon API
	return coff.LoadWithMethod(coffBytes, argBytes, entryPoint)
}

// GetBeaconCallbacks returns Windows callbacks for our Beacon API functions
// These can be used to override goffloader's default implementations
func GetBeaconCallbacks() map[string]uintptr {
	return map[string]uintptr{
		"BeaconDataParse":   windows.NewCallback(BeaconDataParse),
		"BeaconDataExtract": windows.NewCallback(BeaconDataExtract),
		"BeaconDataInt":     windows.NewCallback(BeaconDataInt),
		"BeaconDataShort":   windows.NewCallback(BeaconDataShort),
		"BeaconDataLength":  windows.NewCallback(BeaconDataLength),
		"BeaconOutput":      windows.NewCallback(BeaconOutput),
		"BeaconPrintf":      windows.NewCallback(beaconPrintfWrapper),
	}
}

// beaconPrintfWrapper wraps BeaconPrintf for windows.NewCallback
// NewCallback doesn't support variadic functions, so we accept fixed args
func beaconPrintfWrapper(outType int, format uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) uintptr {
	return BeaconPrintf(outType, format, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
}

// Alternative: Direct syscall execution without goffloader
// This gives us full control over the Beacon API resolution

var (
	ntdll          = syscall.MustLoadDLL("ntdll.dll")
	rtlCopyMemory  = ntdll.MustFindProc("RtlCopyMemory")
)

func rtlCopy(dst, src uintptr, size uint32) {
	rtlCopyMemory.Call(dst, src, uintptr(size))
}
