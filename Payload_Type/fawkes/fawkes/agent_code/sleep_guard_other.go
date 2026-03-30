//go:build !windows

package main

// guardedPages is a no-op on non-Windows platforms.
// VirtualProtect/PAGE_NOACCESS is a Windows-only memory protection mechanism.
type guardedPages struct{}

func guardSleepPages(_ *sleepVault) *guardedPages   { return nil }
func unguardSleepPages(_ *guardedPages, _ *sleepVault) {}
