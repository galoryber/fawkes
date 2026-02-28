//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	kernel32PM                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessMitigationPol = kernel32PM.NewProc("GetProcessMitigationPolicy")
	procSetProcessMitigationPol = kernel32PM.NewProc("SetProcessMitigationPolicy")
)

// Mitigation policy types
const (
	ProcessDEPPolicy                   = 0
	ProcessASLRPolicy                  = 1
	ProcessDynamicCodePolicy           = 2
	ProcessStrictHandleCheckPolicy     = 3
	ProcessSystemCallDisablePolicy     = 4
	ProcessExtensionPointDisablePolicy = 6
	ProcessControlFlowGuardPolicy      = 7
	ProcessSignaturePolicy             = 8
	ProcessFontDisablePolicy           = 9
	ProcessImageLoadPolicy             = 10
	ProcessChildProcessPolicy          = 13
	ProcessUserShadowStackPolicy       = 15
)

// Policy structures — bitfield structs matching Windows definitions.
// Each uses a uint32 Flags field where individual bits represent policy settings.

type processMitigationDEPPolicy struct {
	Flags     uint32
	Permanent uint32 // BOOLEAN
}

type processMitigationASLRPolicy struct {
	Flags uint32
}

type processMitigationDynamicCodePolicy struct {
	Flags uint32
}

type processMitigationStrictHandlePolicy struct {
	Flags uint32
}

type processMitigationSystemCallDisablePolicy struct {
	Flags uint32
}

type processMitigationExtensionPointPolicy struct {
	Flags uint32
}

type processMitigationCFGPolicy struct {
	Flags uint32
}

type processMitigationSignaturePolicy struct {
	Flags uint32
}

type processMitigationFontPolicy struct {
	Flags uint32
}

type processMitigationImageLoadPolicy struct {
	Flags uint32
}

type processMitigationChildProcessPolicy struct {
	Flags uint32
}

type processMitigationUserShadowStackPolicy struct {
	Flags uint32
}

type ProcessMitigationCommand struct{}

func (c *ProcessMitigationCommand) Name() string { return "process-mitigation" }
func (c *ProcessMitigationCommand) Description() string {
	return "Query or set process mitigation policies (DEP, ASLR, CIG, ACG, CFG)"
}

type processMitigationArgs struct {
	Action string `json:"action"` // query, set
	PID    int    `json:"pid"`    // target PID (0 = self)
	Policy string `json:"policy"` // policy to set: cig, acg, child-block, dep, cfg
}

func (c *ProcessMitigationCommand) Execute(task structs.Task) structs.CommandResult {
	var args processMitigationArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			args.Action = "query"
		}
	}
	if args.Action == "" {
		args.Action = "query"
	}

	switch strings.ToLower(args.Action) {
	case "query":
		return queryMitigationPolicies(args.PID)
	case "set":
		return setMitigationPolicy(args.Policy)
	default:
		return errorResult("Unknown action: " + args.Action + ". Use: query, set")
	}
}

func getProcessHandle(pid int) (windows.Handle, bool, error) {
	if pid == 0 {
		return windows.CurrentProcess(), false, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, false, fmt.Errorf("OpenProcess(%d): %v", pid, err)
	}
	return h, true, nil
}

func queryMitigationPolicies(pid int) structs.CommandResult {
	handle, needClose, err := getProcessHandle(pid)
	if err != nil {
		return errorf("Failed to open process: %v", err)
	}
	if needClose {
		defer windows.CloseHandle(handle)
	}

	var sb strings.Builder
	if pid == 0 {
		sb.WriteString("Process Mitigation Policies (self):\n")
	} else {
		sb.WriteString(fmt.Sprintf("Process Mitigation Policies (PID %d):\n", pid))
	}
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	// DEP
	var dep processMitigationDEPPolicy
	if getMitigationPolicy(handle, ProcessDEPPolicy, unsafe.Pointer(&dep), unsafe.Sizeof(dep)) {
		sb.WriteString(fmt.Sprintf("DEP (Data Execution Prevention):\n"))
		sb.WriteString(fmt.Sprintf("  Enabled:            %v\n", dep.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  ATL Thunk Emulation: %v\n", dep.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  Permanent:          %v\n", dep.Permanent != 0))
	} else {
		sb.WriteString("DEP: [query failed]\n")
	}

	// ASLR
	var aslr processMitigationASLRPolicy
	if getMitigationPolicy(handle, ProcessASLRPolicy, unsafe.Pointer(&aslr), unsafe.Sizeof(aslr)) {
		sb.WriteString(fmt.Sprintf("ASLR (Address Space Layout Randomization):\n"))
		sb.WriteString(fmt.Sprintf("  Bottom-Up:          %v\n", aslr.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Force Relocate:     %v\n", aslr.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  High Entropy:       %v\n", aslr.Flags&0x4 != 0))
		sb.WriteString(fmt.Sprintf("  Disallow Stripped:  %v\n", aslr.Flags&0x8 != 0))
	} else {
		sb.WriteString("ASLR: [query failed]\n")
	}

	// Dynamic Code (ACG)
	var dynCode processMitigationDynamicCodePolicy
	if getMitigationPolicy(handle, ProcessDynamicCodePolicy, unsafe.Pointer(&dynCode), unsafe.Sizeof(dynCode)) {
		sb.WriteString(fmt.Sprintf("ACG (Arbitrary Code Guard):\n"))
		sb.WriteString(fmt.Sprintf("  Prohibit Dynamic Code: %v\n", dynCode.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Allow Thread Opt-Out:  %v\n", dynCode.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  Allow Remote Downgrade: %v\n", dynCode.Flags&0x4 != 0))
	} else {
		sb.WriteString("ACG: [query failed]\n")
	}

	// Strict Handle Check
	var strictHandle processMitigationStrictHandlePolicy
	if getMitigationPolicy(handle, ProcessStrictHandleCheckPolicy, unsafe.Pointer(&strictHandle), unsafe.Sizeof(strictHandle)) {
		sb.WriteString(fmt.Sprintf("Strict Handle Check:\n"))
		sb.WriteString(fmt.Sprintf("  Raise Exception on Invalid Handle: %v\n", strictHandle.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Handle Exceptions Permanently:     %v\n", strictHandle.Flags&0x2 != 0))
	} else {
		sb.WriteString("Strict Handle Check: [query failed]\n")
	}

	// System Call Disable
	var sysCall processMitigationSystemCallDisablePolicy
	if getMitigationPolicy(handle, ProcessSystemCallDisablePolicy, unsafe.Pointer(&sysCall), unsafe.Sizeof(sysCall)) {
		sb.WriteString(fmt.Sprintf("System Call Disable:\n"))
		sb.WriteString(fmt.Sprintf("  Disallow Win32k Calls: %v\n", sysCall.Flags&0x1 != 0))
	} else {
		sb.WriteString("System Call Disable: [query failed]\n")
	}

	// Extension Point Disable
	var extPt processMitigationExtensionPointPolicy
	if getMitigationPolicy(handle, ProcessExtensionPointDisablePolicy, unsafe.Pointer(&extPt), unsafe.Sizeof(extPt)) {
		sb.WriteString(fmt.Sprintf("Extension Point Disable:\n"))
		sb.WriteString(fmt.Sprintf("  Disable Extension Points: %v\n", extPt.Flags&0x1 != 0))
	} else {
		sb.WriteString("Extension Point Disable: [query failed]\n")
	}

	// Control Flow Guard (CFG)
	var cfg processMitigationCFGPolicy
	if getMitigationPolicy(handle, ProcessControlFlowGuardPolicy, unsafe.Pointer(&cfg), unsafe.Sizeof(cfg)) {
		sb.WriteString(fmt.Sprintf("CFG (Control Flow Guard):\n"))
		sb.WriteString(fmt.Sprintf("  Enabled:             %v\n", cfg.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Export Suppression:  %v\n", cfg.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  Strict Mode:         %v\n", cfg.Flags&0x4 != 0))
	} else {
		sb.WriteString("CFG: [query failed]\n")
	}

	// Binary Signature (CIG)
	var sig processMitigationSignaturePolicy
	if getMitigationPolicy(handle, ProcessSignaturePolicy, unsafe.Pointer(&sig), unsafe.Sizeof(sig)) {
		sb.WriteString(fmt.Sprintf("CIG (Code Integrity Guard):\n"))
		sb.WriteString(fmt.Sprintf("  Microsoft Signed Only: %v\n", sig.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Store Signed Only:     %v\n", sig.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  Mitigation Opt-In:     %v\n", sig.Flags&0x4 != 0))
	} else {
		sb.WriteString("CIG: [query failed]\n")
	}

	// Font Disable
	var font processMitigationFontPolicy
	if getMitigationPolicy(handle, ProcessFontDisablePolicy, unsafe.Pointer(&font), unsafe.Sizeof(font)) {
		sb.WriteString(fmt.Sprintf("Font Disable:\n"))
		sb.WriteString(fmt.Sprintf("  Disable Non-System Fonts: %v\n", font.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Audit Non-System Fonts:   %v\n", font.Flags&0x2 != 0))
	} else {
		sb.WriteString("Font Disable: [query failed]\n")
	}

	// Image Load
	var imgLoad processMitigationImageLoadPolicy
	if getMitigationPolicy(handle, ProcessImageLoadPolicy, unsafe.Pointer(&imgLoad), unsafe.Sizeof(imgLoad)) {
		sb.WriteString(fmt.Sprintf("Image Load:\n"))
		sb.WriteString(fmt.Sprintf("  No Remote Images:        %v\n", imgLoad.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  No Low Mandatory Images: %v\n", imgLoad.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  Prefer System32:         %v\n", imgLoad.Flags&0x4 != 0))
	} else {
		sb.WriteString("Image Load: [query failed]\n")
	}

	// Child Process Policy
	var child processMitigationChildProcessPolicy
	if getMitigationPolicy(handle, ProcessChildProcessPolicy, unsafe.Pointer(&child), unsafe.Sizeof(child)) {
		sb.WriteString(fmt.Sprintf("Child Process:\n"))
		sb.WriteString(fmt.Sprintf("  No Child Process Creation: %v\n", child.Flags&0x1 != 0))
	} else {
		sb.WriteString("Child Process: [query failed]\n")
	}

	// User Shadow Stack (CET)
	var shadowStack processMitigationUserShadowStackPolicy
	if getMitigationPolicy(handle, ProcessUserShadowStackPolicy, unsafe.Pointer(&shadowStack), unsafe.Sizeof(shadowStack)) {
		sb.WriteString(fmt.Sprintf("CET (Shadow Stack):\n"))
		sb.WriteString(fmt.Sprintf("  Enabled:           %v\n", shadowStack.Flags&0x1 != 0))
		sb.WriteString(fmt.Sprintf("  Strict Mode:       %v\n", shadowStack.Flags&0x2 != 0))
		sb.WriteString(fmt.Sprintf("  Set Context IP:    %v\n", shadowStack.Flags&0x4 != 0))
	} else {
		sb.WriteString("CET: [query failed]\n")
	}

	return successResult(sb.String())
}

func setMitigationPolicy(policy string) structs.CommandResult {
	if policy == "" {
		return errorResult("Error: policy parameter required. Options: cig, acg, child-block, dep, cfg, ext-disable, image-restrict, font-disable")
	}

	switch strings.ToLower(policy) {
	case "cig":
		// Enable Microsoft-signed-only DLL loading (blocks unsigned DLLs including most EDR)
		var sig processMitigationSignaturePolicy
		sig.Flags = 0x1 // MicrosoftSignedOnly
		return applyMitigationPolicy(ProcessSignaturePolicy, unsafe.Pointer(&sig), unsafe.Sizeof(sig),
			"CIG (Code Integrity Guard) — Microsoft-signed DLLs only")

	case "acg":
		// Prohibit dynamic code generation
		var dynCode processMitigationDynamicCodePolicy
		dynCode.Flags = 0x1 // ProhibitDynamicCode
		return applyMitigationPolicy(ProcessDynamicCodePolicy, unsafe.Pointer(&dynCode), unsafe.Sizeof(dynCode),
			"ACG (Arbitrary Code Guard) — dynamic code prohibited")

	case "child-block":
		// Block child process creation
		var child processMitigationChildProcessPolicy
		child.Flags = 0x1 // NoChildProcessCreation
		return applyMitigationPolicy(ProcessChildProcessPolicy, unsafe.Pointer(&child), unsafe.Sizeof(child),
			"Child process creation blocked")

	case "dep":
		// Enable DEP
		var dep processMitigationDEPPolicy
		dep.Flags = 0x1 // Enable
		dep.Permanent = 1
		return applyMitigationPolicy(ProcessDEPPolicy, unsafe.Pointer(&dep), unsafe.Sizeof(dep),
			"DEP (Data Execution Prevention) enabled permanently")

	case "cfg":
		// Enable Control Flow Guard
		var cfg processMitigationCFGPolicy
		cfg.Flags = 0x1 // EnableControlFlowGuard
		return applyMitigationPolicy(ProcessControlFlowGuardPolicy, unsafe.Pointer(&cfg), unsafe.Sizeof(cfg),
			"CFG (Control Flow Guard) enabled")

	case "ext-disable":
		// Disable extension points (AppInit DLLs, etc.)
		var ext processMitigationExtensionPointPolicy
		ext.Flags = 0x1 // DisableExtensionPoints
		return applyMitigationPolicy(ProcessExtensionPointDisablePolicy, unsafe.Pointer(&ext), unsafe.Sizeof(ext),
			"Extension points disabled (AppInit DLLs, etc.)")

	case "image-restrict":
		// Block remote images and low mandatory label images, prefer System32
		var img processMitigationImageLoadPolicy
		img.Flags = 0x7 // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
		return applyMitigationPolicy(ProcessImageLoadPolicy, unsafe.Pointer(&img), unsafe.Sizeof(img),
			"Image load restricted (no remote, no low-label, prefer System32)")

	case "font-disable":
		// Block non-system fonts
		var font processMitigationFontPolicy
		font.Flags = 0x1 // DisableNonSystemFonts
		return applyMitigationPolicy(ProcessFontDisablePolicy, unsafe.Pointer(&font), unsafe.Sizeof(font),
			"Non-system fonts disabled")

	default:
		return errorf("Unknown policy: %s. Options: cig, acg, child-block, dep, cfg, ext-disable, image-restrict, font-disable", policy)
	}
}

func getMitigationPolicy(handle windows.Handle, policyType int, buf unsafe.Pointer, size uintptr) bool {
	ret, _, _ := procGetProcessMitigationPol.Call(
		uintptr(handle),
		uintptr(policyType),
		uintptr(buf),
		size,
	)
	return ret != 0
}

func applyMitigationPolicy(policyType int, buf unsafe.Pointer, size uintptr, description string) structs.CommandResult {
	ret, _, err := procSetProcessMitigationPol.Call(
		uintptr(policyType),
		uintptr(buf),
		size,
	)
	if ret == 0 {
		return errorf("Failed to set %s: %v", description, err)
	}
	return successf("Successfully set: %s", description)
}
