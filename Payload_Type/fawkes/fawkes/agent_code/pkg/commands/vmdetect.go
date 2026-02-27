package commands

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// VmDetectCommand detects virtual machine and hypervisor environments.
type VmDetectCommand struct{}

func (c *VmDetectCommand) Name() string        { return "vm-detect" }
func (c *VmDetectCommand) Description() string { return "Detect virtual machine and hypervisor environment" }

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

func (c *VmDetectCommand) Execute(task structs.Task) structs.CommandResult {
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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
		if iface.HardwareAddr == nil || len(iface.HardwareAddr) < 3 {
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
		if strings.Contains(content, "hypervisor") {
			evidence = append(evidence, vmEvidence{"CPU hypervisor flag", "VM", "hypervisor bit set in CPUID"})
		} else {
			evidence = append(evidence, vmEvidence{"CPU hypervisor flag", "clean", "no hypervisor flag"})
		}
	}

	return evidence, detected
}

func vmDetectDarwin() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	// Check hw.model via sysctl file
	// On macOS VMs, model often reveals virtualization
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		// macOS doesn't have /proc, so this won't hit normally
		_ = data
	}

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
		`C:\Program Files\VMware\VMware Tools`:                       "VMware",
		`C:\Program Files\Oracle\VirtualBox Guest Additions`:         "VirtualBox",
		`C:\Program Files\Parallels\Parallels Tools`:                "Parallels",
		`C:\Windows\System32\drivers\VBoxMouse.sys`:                 "VirtualBox",
		`C:\Windows\System32\drivers\vmhgfs.sys`:                    "VMware",
		`C:\Windows\System32\drivers\vmci.sys`:                      "VMware",
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
