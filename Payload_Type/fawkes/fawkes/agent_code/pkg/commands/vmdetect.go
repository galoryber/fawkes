package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
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

func vmDetectLinux() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	// Check /sys/class/dmi/id/product_name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.TrimSpace(string(data))
		structs.ZeroBytes(data) // opsec
		productLower := strings.ToLower(product)
		vm := ""
		if strings.Contains(productLower, "virtualbox") {
			vm = "VirtualBox"
		} else if strings.Contains(productLower, "vmware") {
			vm = "VMware"
		} else if strings.Contains(productLower, "virtual machine") {
			vm = "Hyper-V"
		} else if strings.Contains(productLower, "kvm") || strings.Contains(productLower, "qemu") {
			vm = "QEMU/KVM"
		} else if strings.Contains(productLower, "xen") {
			vm = "Xen"
		} else if strings.Contains(productLower, "parallels") {
			vm = "Parallels"
		}
		if vm != "" {
			evidence = append(evidence, vmEvidence{"DMI product_name", "VM", fmt.Sprintf("%s → %s", product, vm)})
			detected = vm
		} else {
			evidence = append(evidence, vmEvidence{"DMI product_name", "clean", product})
		}
	}

	// Check /sys/class/dmi/id/sys_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.TrimSpace(string(data))
		structs.ZeroBytes(data) // opsec
		vendorLower := strings.ToLower(vendor)
		vendorVM := ""
		if strings.Contains(vendorLower, "vmware") {
			vendorVM = "VMware"
		} else if strings.Contains(vendorLower, "innotek") {
			vendorVM = "VirtualBox"
		} else if strings.Contains(vendorLower, "microsoft") {
			vendorVM = "Hyper-V"
		} else if strings.Contains(vendorLower, "qemu") {
			vendorVM = "QEMU/KVM"
		} else if strings.Contains(vendorLower, "xen") {
			vendorVM = "Xen"
		} else if strings.Contains(vendorLower, "parallels") {
			vendorVM = "Parallels"
		} else if strings.Contains(vendorLower, "amazon") {
			vendorVM = "AWS"
		}
		if vendorVM != "" {
			evidence = append(evidence, vmEvidence{"DMI sys_vendor", "VM", vendor})
			if detected == "" {
				detected = vendorVM
			}
		} else {
			evidence = append(evidence, vmEvidence{"DMI sys_vendor", "clean", vendor})
		}
	}

	// Check /sys/class/dmi/id/bios_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/bios_vendor"); err == nil {
		bios := strings.TrimSpace(string(data))
		structs.ZeroBytes(data) // opsec
		biosLower := strings.ToLower(bios)
		biosVM := ""
		if strings.Contains(biosLower, "innotek") {
			biosVM = "VirtualBox"
		} else if strings.Contains(biosLower, "seabios") {
			biosVM = "QEMU/KVM"
		} else if strings.Contains(biosLower, "xen") {
			biosVM = "Xen"
		} else if strings.Contains(biosLower, "phoenix") {
			biosVM = "VM (Phoenix BIOS)"
		}
		if biosVM != "" {
			evidence = append(evidence, vmEvidence{"DMI bios_vendor", "VM", bios})
			if detected == "" {
				detected = biosVM
			}
		} else {
			evidence = append(evidence, vmEvidence{"DMI bios_vendor", "info", bios})
		}
	}

	// Check /proc/scsi/scsi for virtual disk
	if data, err := os.ReadFile("/proc/scsi/scsi"); err == nil {
		content := strings.ToLower(string(data))
		structs.ZeroBytes(data) // opsec
		scsiVM := ""
		if strings.Contains(content, "vmware") {
			scsiVM = "VMware"
		} else if strings.Contains(content, "vbox") {
			scsiVM = "VirtualBox"
		} else if strings.Contains(content, "qemu") || strings.Contains(content, "virtio") {
			scsiVM = "QEMU/KVM"
		}
		if scsiVM != "" {
			evidence = append(evidence, vmEvidence{"SCSI devices", "VM", scsiVM + " virtual disk"})
			if detected == "" {
				detected = scsiVM
			}
		}
	}

	// Check hypervisor flag in cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := string(data)
		structs.ZeroBytes(data) // opsec: cpuinfo may reveal hardware details
		if strings.Contains(content, "hypervisor") {
			evidence = append(evidence, vmEvidence{"CPU hypervisor flag", "VM", "hypervisor bit set in CPUID"})
		} else {
			evidence = append(evidence, vmEvidence{"CPU hypervisor flag", "clean", "no hypervisor flag"})
		}
	}

	// Check /sys/hypervisor/type (Xen, KVM)
	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		hyperType := strings.TrimSpace(string(data))
		structs.ZeroBytes(data) // opsec
		if hyperType != "" {
			vm := classifyHypervisorType(hyperType)
			if vm != "" {
				evidence = append(evidence, vmEvidence{"Hypervisor type", "VM", fmt.Sprintf("%s → %s", hyperType, vm)})
				if detected == "" {
					detected = vm
				}
			}
		}
	}

	// Check /sys/class/dmi/id/board_name for cloud providers
	if data, err := os.ReadFile("/sys/class/dmi/id/board_name"); err == nil {
		board := strings.TrimSpace(string(data))
		structs.ZeroBytes(data) // opsec
		if cloud := classifyCloudBoard(board); cloud != "" {
			evidence = append(evidence, vmEvidence{"DMI board_name", "cloud", fmt.Sprintf("%s → %s", board, cloud)})
			if detected == "" {
				detected = cloud
			}
		}
	}

	// Check for VM guest agent processes via /proc
	procEvidence, procVM := vmDetectLinuxProcesses()
	evidence = append(evidence, procEvidence...)
	if procVM != "" && detected == "" {
		detected = procVM
	}

	return evidence, detected
}

// vmGuestProcesses maps process names to VM types for guest agent detection.
var vmGuestProcesses = map[string]string{
	"vmtoolsd":          "VMware",
	"vmware-vmblock":    "VMware",
	"vmhgfs-fuse":       "VMware",
	"VBoxService":       "VirtualBox",
	"VBoxClient":        "VirtualBox",
	"qemu-ga":           "QEMU/KVM",
	"spice-vdagent":     "QEMU/KVM",
	"hv_kvp_daemon":     "Hyper-V",
	"hv_vss_daemon":     "Hyper-V",
	"hv_fcopy_daemon":   "Hyper-V",
	"xe-daemon":         "Xen",
	"xenstore":          "Xen",
	"prl_tools_service": "Parallels",
}

// classifyHypervisorType maps /sys/hypervisor/type values to VM names.
func classifyHypervisorType(hyperType string) string {
	switch strings.ToLower(hyperType) {
	case "xen":
		return "Xen"
	case "kvm":
		return "KVM"
	default:
		return hyperType
	}
}

// classifyCloudBoard maps DMI board_name values to cloud provider names.
func classifyCloudBoard(boardName string) string {
	lower := strings.ToLower(boardName)
	switch {
	case strings.Contains(lower, "google compute"):
		return "GCP"
	case strings.Contains(lower, "amazon ec2"):
		return "AWS EC2"
	case strings.Contains(lower, "virtual machine"):
		// Azure uses "Virtual Machine" as board_name
		return ""
	default:
		return ""
	}
}

// classifyVMProcess checks if a process name indicates a VM guest agent.
// Returns the VM type or empty string if not recognized.
func classifyVMProcess(procName string) string {
	if vm, ok := vmGuestProcesses[procName]; ok {
		return vm
	}
	return ""
}

// vmDetectLinuxProcesses scans /proc for VM guest agent processes.
func vmDetectLinuxProcesses() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return evidence, ""
	}

	found := make(map[string]string) // process name → VM type (deduplicate)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only check numeric directories (PIDs)
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", name))
		if err != nil {
			continue
		}
		procName := strings.TrimSpace(string(comm))
		if vm := classifyVMProcess(procName); vm != "" {
			found[procName] = vm
		}
	}

	if len(found) > 0 {
		for proc, vm := range found {
			evidence = append(evidence, vmEvidence{"VM Guest Process", "VM", fmt.Sprintf("%s → %s", proc, vm)})
			if detected == "" {
				detected = vm
			}
		}
	} else {
		evidence = append(evidence, vmEvidence{"VM Guest Process Scan", "clean", "no VM guest agents found"})
	}

	return evidence, detected
}

func vmDetectDarwin() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	// Check for known VM kext/processes
	vmKexts := map[string]string{
		"/Library/Application Support/VMware Tools": "VMware",
		"/Library/Extensions/VBoxGuest.kext":        "VirtualBox",
		"/Library/Extensions/ParallelsVmm.kext":     "Parallels",
	}

	for path, vm := range vmKexts {
		if _, err := os.Stat(path); err == nil {
			evidence = append(evidence, vmEvidence{"VM Tools", "VM", fmt.Sprintf("%s → %s", path, vm)})
			detected = vm
		}
	}

	if len(evidence) == 0 {
		evidence = append(evidence, vmEvidence{"VM Tools", "clean", "no VM tools/kexts found"})
	}

	return evidence, detected
}

func vmDetectWindows() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	// Check for VM-specific files/directories
	vmPaths := map[string]string{
		`C:\Program Files\VMware\VMware Tools`:               "VMware",
		`C:\Program Files\Oracle\VirtualBox Guest Additions`: "VirtualBox",
		`C:\Program Files\Parallels\Parallels Tools`:         "Parallels",
		`C:\Windows\System32\drivers\VBoxMouse.sys`:          "VirtualBox",
		`C:\Windows\System32\drivers\vmhgfs.sys`:             "VMware",
		`C:\Windows\System32\drivers\vmci.sys`:               "VMware",
	}

	for path, vm := range vmPaths {
		if _, err := os.Stat(path); err == nil {
			evidence = append(evidence, vmEvidence{"VM Files", "VM", fmt.Sprintf("%s → %s", path, vm)})
			if detected == "" {
				detected = vm
			}
		}
	}

	// Check for Hyper-V generation ID
	if _, err := os.Stat(`C:\Windows\System32\drivers\VMBusHID.sys`); err == nil {
		evidence = append(evidence, vmEvidence{"Hyper-V bus driver", "VM", "VMBusHID.sys present"})
		if detected == "" {
			detected = "Hyper-V"
		}
	}

	if len(evidence) == 0 {
		evidence = append(evidence, vmEvidence{"VM Files Check", "clean", "no VM files found"})
	}

	return evidence, detected
}
