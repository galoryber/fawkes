//go:build windows
// +build windows

package main

import (
	"golang.org/x/sys/windows"
)

func getIntegrityLevel() int {
	// Integrity levels for Mythic:
	// 1 = Low integrity (untrusted)
	// 2 = Medium integrity (standard user)
	// 3 = High integrity (administrator)
	// 4 = System integrity (SYSTEM)

	// Get the current process token
	var token windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token)
	if err != nil {
		// If we can't get the token, assume medium integrity
		return 2
	}
	defer token.Close()

	// Check if running as SYSTEM by comparing user SID
	tokenUser, err := token.GetTokenUser()
	if err == nil {
		// SYSTEM SID: S-1-5-18
		systemSID, _ := windows.StringToSid("S-1-5-18")
		if tokenUser.User.Sid.Equals(systemSID) {
			return 4 // SYSTEM
		}
	}

	// Check if elevated (running as administrator)
	elevated := token.IsElevated()
	if elevated {
		return 3 // High integrity / Administrator
	}

	// Default to medium integrity for non-elevated users
	return 2
}
