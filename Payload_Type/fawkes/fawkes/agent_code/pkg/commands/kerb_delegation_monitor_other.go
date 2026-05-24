//go:build !windows
// +build !windows

package commands

import "fawkes/pkg/structs"

// kdMonitor is a Windows-only feature; return an informative error on other platforms.
func kdMonitor(args kerbDelegArgs) structs.CommandResult {
	return errorResult("Error: kerb-delegation monitor requires Windows (uses LSA ticket enumeration APIs)")
}
