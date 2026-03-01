package commands

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// JobsCommand lists currently running tasks
type JobsCommand struct{}

func (c *JobsCommand) Name() string        { return "jobs" }
func (c *JobsCommand) Description() string { return "List currently running tasks" }

func (c *JobsCommand) Execute(task structs.Task) structs.CommandResult {
	tasks := GetRunningTasks()

	if len(tasks) == 0 {
		return structs.CommandResult{
			Output:    "No running tasks",
			Status:    "success",
			Completed: true,
		}
	}

	// Sort by start time for consistent output
	type entry struct {
		id   string
		task *structs.Task
	}
	entries := make([]entry, 0, len(tasks))
	for id, t := range tasks {
		// Skip the jobs command itself
		if id == task.ID {
			continue
		}
		entries = append(entries, entry{id, t})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].task.StartTime.Before(entries[j].task.StartTime)
	})

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "No running tasks (only this jobs command)",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-36s  %-20s  %s\n", "Task ID", "Command", "Running"))
	sb.WriteString(strings.Repeat("-", 72) + "\n")

	for _, e := range entries {
		duration := time.Since(e.task.StartTime).Truncate(time.Second)
		sb.WriteString(fmt.Sprintf("%-36s  %-20s  %s\n", e.id, e.task.Command, duration))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
