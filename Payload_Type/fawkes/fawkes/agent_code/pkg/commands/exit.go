package commands

import (
	"log"
	"os"
	"time"

	"fawkes/pkg/structs"
)

// ExitCommand implements the exit command
type ExitCommand struct{}

// Name returns the command name
func (c *ExitCommand) Name() string {
	return "exit"
}

// Description returns the command description
func (c *ExitCommand) Description() string {
	return "Exit the current session and kill the agent"
}

// Execute executes the exit command
func (c *ExitCommand) Execute(task structs.Task) structs.CommandResult {
	log.Printf("[INFO] Exit command received, terminating agent")

	// Send response before exiting
	result := structs.CommandResult{
		Output:    "Agent exiting...",
		Status:    "success",
		Completed: true,
	}

	// Exit in a goroutine after a short delay to allow the response to be posted
	go func() {
		time.Sleep(3 * time.Second)
		log.Printf("[INFO] Agent shutting down")
		os.Exit(0)
	}()

	return result
}
