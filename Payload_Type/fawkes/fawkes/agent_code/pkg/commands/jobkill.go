package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

// JobkillCommand stops a running task by ID
type JobkillCommand struct{}

func (c *JobkillCommand) Name() string        { return "jobkill" }
func (c *JobkillCommand) Description() string { return "Stop a running task by task ID" }

type jobkillArgs struct {
	ID string `json:"id"`
}

func (c *JobkillCommand) Execute(task structs.Task) structs.CommandResult {
	var args jobkillArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse arguments: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.ID == "" {
		return structs.CommandResult{
			Output:    "Task ID is required",
			Status:    "error",
			Completed: true,
		}
	}

	target, ok := GetRunningTask(args.ID)
	if !ok {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No running task found with ID: %s", args.ID),
			Status:    "error",
			Completed: true,
		}
	}

	target.SetStop()
	return structs.CommandResult{
		Output:    fmt.Sprintf("Stop signal sent to task %s (%s)", args.ID, target.Command),
		Status:    "success",
		Completed: true,
	}
}
