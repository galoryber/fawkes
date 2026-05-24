//go:build !windows

package commands

import "fawkes/pkg/structs"

func securityInfoKernelDrivers() structs.CommandResult {
	return errorf("kernel driver enumeration is only available on Windows (requires NtQuerySystemInformation)")
}
