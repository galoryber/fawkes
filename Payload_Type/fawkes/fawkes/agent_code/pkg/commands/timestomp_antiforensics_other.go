//go:build !windows

package commands

import "fawkes/pkg/structs"

func timestompCleanPrefetch(_ string) structs.CommandResult {
	return errorResult("clean-prefetch is Windows only — Prefetch files are a Windows execution trace")
}
