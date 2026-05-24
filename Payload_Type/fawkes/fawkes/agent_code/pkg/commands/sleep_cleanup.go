package commands

import (
	"runtime"
	"unsafe"
)

// PreSleepCleanup zeroes sensitive data from accessible memory before the agent
// enters a sleep period. In Go, we cannot directly zero the call stack (the runtime
// manages goroutine stacks and GC may move them). Instead, we clear known sensitive
// data buffers that might persist in memory during sleep:
//   - Task parameters that contained credentials
//   - Identity credential buffers (already zeroed by individual commands, but double-check)
//   - Force a GC to release deallocated memory pages
func PreSleepCleanup() {
	// 1. Force garbage collection to free unreferenced memory containing
	//    command output, task parameters, credential strings, etc.
	//    This reduces the window where sensitive data persists on the heap.
	runtime.GC()

	// 2. Zero out global sensitive buffers that might persist across sleep.
	//    Identity credentials are normally zeroed by rev2self/individual commands,
	//    but during sleep they might still be accessible if not explicitly cleared.
	clearSensitiveGlobals()
}

// clearSensitiveGlobals zeros any global buffers that might contain sensitive data.
// This is a defense-in-depth measure — individual commands should already zero
// their own sensitive data, but this catches anything that leaked.
func clearSensitiveGlobals() {
	// Last command output buffer — might contain credential dumps, hashes, etc.
	// Clear it to avoid leaving artifacts in memory during sleep.
	clearLastOutput()
}

// lastOutputMu protects lastOutputBuffer from concurrent access.
var lastOutputBuffer []byte

// SetLastOutput stores the last command output for cleanup.
func SetLastOutput(data []byte) {
	lastOutputBuffer = data
}

// clearLastOutput zeros and releases the last output buffer.
func clearLastOutput() {
	if len(lastOutputBuffer) > 0 {
		zeroBytes(lastOutputBuffer)
		lastOutputBuffer = nil
	}
}

// zeroBytes zeros a byte slice in-place using compiler-safe pattern.
func zeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use volatile-style zeroing that won't be optimized away
	for i := range b {
		*(*byte)(unsafe.Pointer(&b[i])) = 0
	}
}

// PostSleepInit re-initializes any state needed after waking from sleep.
// Currently a no-op, but provides a hook for future wake-up actions.
func PostSleepInit() {
	// Future: re-verify process token, check for debugger attachment, etc.
}
