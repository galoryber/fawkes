package commands

// blockDLLsEnabled controls whether child processes block non-Microsoft DLLs.
// Set by the blockDLLs build parameter. Only effective on Windows.
var blockDLLsEnabled bool

// SetBlockDLLs enables or disables BlockDLLs mitigation for child processes.
func SetBlockDLLs(enabled bool) {
	blockDLLsEnabled = enabled
}
