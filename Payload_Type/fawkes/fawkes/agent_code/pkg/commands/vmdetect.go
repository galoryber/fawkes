package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// VmDetectCommand detects virtual machine and hypervisor environments.
type VmDetectCommand struct{}

func (c *VmDetectCommand) Name() string { return "vm-detect" }
func (c *VmDetectCommand) Description() string {
	return "Detect virtual machine and hypervisor environment"
}

type vmEvidence struct {
	Check   string
	Result  string
	Details string
}

// Known VM MAC address prefixes (OUI)
var vmMACPrefixes = map[string]string{
	"00:05:69": "VMware",
	"00:0c:29": "VMware",
	"00:1c:14": "VMware",
	"00:50:56": "VMware",
	"08:00:27": "VirtualBox",
	"0a:00:27": "VirtualBox",
	"00:15:5d": "Hyper-V",
	"00:16:3e": "Xen",
	"52:54:00": "QEMU/KVM",
	"fa:16:3e": "OpenStack",
}

type vmdetectArgs struct {
	Action string `json:"action"` // detect (default), sandbox
}

func (c *VmDetectCommand) Execute(task structs.Task) structs.CommandResult {
	var args vmdetectArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}
	if args.Action == "" {
		args.Action = "detect"
	}

	switch args.Action {
	case "sandbox":
		result := vmSandboxDetect()
		return successResult(formatSandboxResult(result))
	case "detect":
		// Fall through to existing VM detection logic
	default:
		return errorf("Error: unknown action '%s' (use detect or sandbox)", args.Action)
	}

	var evidence []vmEvidence
	detected := "none"

	// Cross-platform: check MAC addresses
	macResult, macVM := vmCheckMAC()
	evidence = append(evidence, macResult...)
	if macVM != "" {
		detected = macVM
	}

	// Platform-specific checks
	switch runtime.GOOS {
	case "linux":
		linuxEvidence, linuxVM := vmDetectLinux()
		evidence = append(evidence, linuxEvidence...)
		if linuxVM != "" {
			detected = linuxVM
		}
	case "darwin":
		darwinEvidence, darwinVM := vmDetectDarwin()
		evidence = append(evidence, darwinEvidence...)
		if darwinVM != "" {
			detected = darwinVM
		}
	case "windows":
		winEvidence, winVM := vmDetectWindows()
		evidence = append(evidence, winEvidence...)
		if winVM != "" {
			detected = winVM
		}
	}

	var sb strings.Builder
	sb.WriteString("[*] VM/Hypervisor Detection\n\n")

	if detected != "none" {
		sb.WriteString(fmt.Sprintf("  Hypervisor: %s\n\n", detected))
	} else {
		sb.WriteString("  Hypervisor: none detected (bare metal likely)\n\n")
	}

	sb.WriteString(fmt.Sprintf("%-35s %-12s %s\n", "Check", "Result", "Details"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, e := range evidence {
		sb.WriteString(fmt.Sprintf("%-35s %-12s %s\n", e.Check, e.Result, e.Details))
	}

	return successResult(sb.String())
}

func vmCheckMAC() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	ifaces, err := net.Interfaces()
	if err != nil {
		evidence = append(evidence, vmEvidence{"MAC Address Check", "error", fmt.Sprintf("%v", err)})
		return evidence, ""
	}

	for _, iface := range ifaces {
		if len(iface.HardwareAddr) < 3 {
			continue
		}
		mac := iface.HardwareAddr.String()
		prefix := mac[:8]
		if vm, ok := vmMACPrefixes[prefix]; ok {
			evidence = append(evidence, vmEvidence{"MAC Address", "VM", fmt.Sprintf("%s → %s (%s)", iface.Name, mac, vm)})
			if detected == "" {
				detected = vm
			}
		}
	}

	if len(evidence) == 0 {
		evidence = append(evidence, vmEvidence{"MAC Address Check", "clean", "no VM MAC prefixes found"})
	}

	return evidence, detected
}

// Platform-specific detection functions (vmDetectLinux, vmDetectDarwin, vmDetectWindows,
// classifyHypervisorType, classifyCloudBoard, classifyVMProcess, vmDetectLinuxProcesses,
// vmGuestProcesses) are in vmdetect_techniques.go.
