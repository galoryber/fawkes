//go:build !windows
// +build !windows

package commands

import "fawkes/pkg/structs"

func (c *WmiPersistCommand) Execute(task structs.Task) structs.CommandResult {
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		return *errResult
	}
	_ = args
	return errorResult("wmi-persist is only available on Windows")
}
