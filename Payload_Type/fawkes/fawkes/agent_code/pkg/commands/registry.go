package commands

import (
	"log"
	"sync"

	"fawkes/pkg/structs"
)

var (
	commandRegistry = make(map[string]structs.Command)
	registryMutex   sync.RWMutex
)

// Initialize sets up all available commands
func Initialize() {
	log.Printf("[INFO] Initializing command handlers")
	
	// Register commands
	RegisterCommand(&LsCommand{})
	RegisterCommand(&SleepCommand{})
	RegisterCommand(&ExitCommand{})
	
	log.Printf("[INFO] Registered %d command handlers", len(commandRegistry))
}

// RegisterCommand registers a command with the command registry
func RegisterCommand(cmd structs.Command) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	
	commandRegistry[cmd.Name()] = cmd
	// log.Printf("[DEBUG] Registered command: %s", cmd.Name())
}

// GetCommand retrieves a command from the registry
func GetCommand(name string) structs.Command {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	return commandRegistry[name]
}

// GetAllCommands returns all registered commands
func GetAllCommands() map[string]structs.Command {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	commands := make(map[string]structs.Command)
	for name, cmd := range commandRegistry {
		commands[name] = cmd
	}
	
	return commands
}