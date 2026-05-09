//go:build !windows
// +build !windows

package commands

// Stub for non-Windows builds. The full registry-reading helper is in
// lsass_protection_windows.go. The data model (LsassProtectionState plus its
// formatting helpers) lives in lsass_protection.go and is available on every
// platform so unit tests can run on Linux/macOS without a Windows registry.

func detectLsassProtection() LsassProtectionState {
	return LsassProtectionState{Error: "lsass protection detection is windows-only"}
}
