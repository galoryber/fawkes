//go:build windows

package main

import (
	"runtime"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// collectHardwareAttributes gathers stable hardware identifiers on Windows.
// Components: CPU identifier from registry, MachineGuid, architecture.
func collectHardwareAttributes() []byte {
	var parts []string

	parts = append(parts, cpuIdentFromRegistry())
	parts = append(parts, machineGUID())
	parts = append(parts, runtime.GOARCH)

	return []byte("windows:" + strings.Join(parts, "|"))
}

func getCPUBrand() string { return cpuIdentFromRegistry() }

func cpuIdentFromRegistry() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.READ)
	if err != nil {
		return ""
	}
	defer k.Close()
	val, _, err := k.GetStringValue("ProcessorNameString")
	if err != nil {
		val, _, _ = k.GetStringValue("Identifier")
	}
	return strings.TrimSpace(val)
}

func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.READ)
	if err != nil {
		return ""
	}
	defer k.Close()
	val, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(val)
}
