package commands

var blockDLLsEnabled bool
var defaultPPID int

func blockDLLsSet(enabled bool) {
	blockDLLsEnabled = enabled
}

// SetDefaultPPID sets the default parent PID for subprocess commands (run, powershell).
func SetDefaultPPID(ppid int) {
	defaultPPID = ppid
}

// GetDefaultPPID returns the current default parent PID.
func GetDefaultPPID() int {
	return defaultPPID
}
