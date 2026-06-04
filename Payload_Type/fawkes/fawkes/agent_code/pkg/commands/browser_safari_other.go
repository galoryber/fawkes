//go:build !darwin

package commands

import "fawkes/pkg/structs"

func appendSafariPasswords(result structs.CommandResult) structs.CommandResult {
	return result
}
