//go:build !windows

package commands

import "fawkes/pkg/structs"

func securityInfoMinifilterEnum() structs.CommandResult {
	return errorf("minifilter enumeration is only available on Windows (requires filter manager library)")
}
