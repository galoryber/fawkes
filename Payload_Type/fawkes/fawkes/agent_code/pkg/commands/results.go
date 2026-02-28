package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

// errorResult returns a completed CommandResult with error status.
func errorResult(msg string) structs.CommandResult {
	return structs.CommandResult{
		Output:    msg,
		Status:    "error",
		Completed: true,
	}
}

// errorf returns a completed CommandResult with a formatted error message.
func errorf(format string, args ...interface{}) structs.CommandResult {
	return structs.CommandResult{
		Output:    fmt.Sprintf(format, args...),
		Status:    "error",
		Completed: true,
	}
}

// successResult returns a completed CommandResult with success status.
func successResult(msg string) structs.CommandResult {
	return structs.CommandResult{
		Output:    msg,
		Status:    "completed",
		Completed: true,
	}
}

// successf returns a completed CommandResult with a formatted success message.
func successf(format string, args ...interface{}) structs.CommandResult {
	return structs.CommandResult{
		Output:    fmt.Sprintf(format, args...),
		Status:    "completed",
		Completed: true,
	}
}

// parseArgs unmarshals JSON task params into the target struct.
// Returns a non-zero CommandResult on error (caller should return it).
// Returns a zero-value CommandResult on success (caller should continue).
func parseArgs(params string, target interface{}) (structs.CommandResult, bool) {
	if params == "" {
		return errorResult("Error: parameters required"), false
	}
	if err := json.Unmarshal([]byte(params), target); err != nil {
		return errorf("Error parsing parameters: %v", err), false
	}
	return structs.CommandResult{}, true
}
