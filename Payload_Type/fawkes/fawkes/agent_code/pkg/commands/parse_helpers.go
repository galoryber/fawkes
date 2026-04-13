package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

// unmarshalParams is a generic helper that parses JSON task parameters into a typed struct.
// It handles the common boilerplate of:
//   1. Checking for empty params
//   2. JSON unmarshalling
//   3. Returning a formatted error on failure
//
// Usage:
//   args, err := unmarshalParams[myArgsType](task)
//   if err != nil { return err }
func unmarshalParams[T any](task structs.Task) (T, *structs.CommandResult) {
	var args T
	if task.Params == "" {
		return args, nil
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		result := errorf("Error parsing parameters: %v", err)
		return args, &result
	}
	return args, nil
}

// requireParams is like unmarshalParams but returns an error if params are empty.
// Use this for commands that always require parameters.
//
// Usage:
//   args, err := requireParams[myArgsType](task)
//   if err != nil { return err }
func requireParams[T any](task structs.Task) (T, *structs.CommandResult) {
	var args T
	if task.Params == "" {
		result := errorResult(fmt.Sprintf("Error: parameters required"))
		return args, &result
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		result := errorf("Error parsing parameters: %v", err)
		return args, &result
	}
	return args, nil
}
