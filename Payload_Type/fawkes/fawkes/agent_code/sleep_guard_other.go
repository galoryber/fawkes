//go:build !windows && !linux && !darwin

package main

// guardedPages is a no-op on platforms without mmap/mprotect or VirtualProtect.
type guardedPages struct{}

func guardSleepPages(_ *sleepVault) *guardedPages      { return nil }
func unguardSleepPages(_ *guardedPages, _ *sleepVault) {}
