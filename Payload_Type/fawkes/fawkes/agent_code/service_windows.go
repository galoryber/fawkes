//go:build windows
// +build windows

package main

import (
	"syscall"
	"unsafe"
)

// Minimal Windows SCM service handler. When Fawkes is started by the Service
// Control Manager (e.g., via sc.exe create + sc.exe start), this code registers
// with SCM, sets SERVICE_RUNNING, and then calls runAgent(). Without this, SCM
// kills the process after ~30s because no ServiceMain was registered.
//
// The tryRunAsService() function is called from main() before runAgent(). If the
// process was started by SCM, it blocks and runs the agent in the service context
// (with full service privileges like SeImpersonatePrivilege). If not started by
// SCM, it returns false and main() falls through to normal runAgent().

var (
	advapi32DLL                       = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW   = advapi32DLL.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32DLL.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32DLL.NewProc("SetServiceStatus")
)

// SERVICE_STATUS matches the Win32 SERVICE_STATUS structure.
type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

const (
	serviceWin32OwnProcess = 0x10
	serviceRunning         = 0x04
	serviceStopped         = 0x01
	serviceAcceptStop      = 0x01
)

// serviceTableEntry matches Win32 SERVICE_TABLE_ENTRYW.
type serviceTableEntry struct {
	ServiceName *uint16
	ServiceProc uintptr
}

var svcStatusHandle uintptr

// svcMain is the ServiceMain callback. SCM calls this when the service starts.
func svcMain(argc uint32, argv **uint16) uintptr {
	// Register a control handler (required by SCM)
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
	return 0
}

// svcCtrlHandler handles SCM control requests (stop, shutdown, etc.).
// We accept stop requests but don't actively handle them — the agent has
// its own shutdown logic via kill date and signal handling.
func svcCtrlHandler(control, eventType, eventData, context uintptr) uintptr {
	if control == 1 { // SERVICE_CONTROL_STOP
		status := serviceStatus{
			ServiceType:  serviceWin32OwnProcess,
			CurrentState: serviceStopped,
		}
		procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&status)))
	}
	return 0
}

// tryRunAsService attempts to register with the Windows Service Control Manager.
// If the process was started by SCM, this function blocks and runs the agent
// as a service (returning true when done). If the process was NOT started by
// SCM (normal execution), StartServiceCtrlDispatcher fails and we return false.
func tryRunAsService() bool {
	emptyName, _ := syscall.UTF16PtrFromString("")
	entries := [2]serviceTableEntry{
		{
			ServiceName: emptyName,
			ServiceProc: syscall.NewCallback(svcMain),
		},
		{ServiceName: nil, ServiceProc: 0}, // null terminator
	}

	ret, _, _ := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&entries[0])))
	return ret != 0
}
