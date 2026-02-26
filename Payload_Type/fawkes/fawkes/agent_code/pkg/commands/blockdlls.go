package commands

// SetBlockDLLs enables or disables BlockDLLs mitigation for child processes.
// Only effective on Windows; no-op on other platforms.
func SetBlockDLLs(enabled bool) {
	blockDLLsSet(enabled)
}
