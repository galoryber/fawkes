package commands

import (

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
	args, parseErr := unmarshalParams[jobkillArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.ID == "" {
		return errorResult("Task ID is required")
	}

	target, ok := GetRunningTask(args.ID)
	if !ok {
		return errorf("No running task found with ID: %s", args.ID)
	}

	target.SetStop()
	return successf("Stop signal sent to task %s (%s)", args.ID, target.Command)
}
