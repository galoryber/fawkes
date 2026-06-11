package commands

// vmdetect_techniques.go contains platform-specific VM detection techniques
// extracted from vmdetect.go. Includes Linux DMI/procfs checks, guest agent
// process scanning, classifier helpers, and macOS/Windows file checks.

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

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

func vmDetectLinux() ([]vmEvidence, string) {
	var evidence []vmEvidence
	detected := ""

	dmiChecks := []struct {
		path, label, cleanLevel string
		matchers                []vmMatcher
	}{
		{"/sys/class/dmi/id/product_name", "DMI product_name", "clean", []vmMatcher{
			{"virtualbox", "VirtualBox"}, {"vmware", "VMware"}, {"virtual machine", "Hyper-V"},
			{"kvm", "QEMU/KVM"}, {"qemu", "QEMU/KVM"}, {"xen", "Xen"}, {"parallels", "Parallels"},
		}},
		{"/sys/class/dmi/id/sys_vendor", "DMI sys_vendor", "clean", []vmMatcher{
			{"vmware", "VMware"}, {"innotek", "VirtualBox"}, {"microsoft", "Hyper-V"},
			{"qemu", "QEMU/KVM"}, {"xen", "Xen"}, {"parallels", "Parallels"}, {"amazon", "AWS"},
		}},
		{"/sys/class/dmi/id/bios_vendor", "DMI bios_vendor", "info", []vmMatcher{
			{"innotek", "VirtualBox"}, {"seabios", "QEMU/KVM"}, {"xen", "Xen"}, {"phoenix", "VM (Phoenix BIOS)"},
		}},
		{"/proc/scsi/scsi", "SCSI devices", "", []vmMatcher{
			{"vmware", "VMware"}, {"vbox", "VirtualBox"}, {"qemu", "QEMU/KVM"}, {"virtio", "QEMU/KVM"},
		}},
	}

	for _, check := range dmiChecks {
		ev, vm := vmCheckDMIFile(check.path, check.label, check.cleanLevel, check.matchers)
		evidence = append(evidence, ev...)
		if vm != "" && detected == "" {
			detected = vm
		}
	}

	// Check hypervisor flag in cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := string(data)
		structs.ZeroBytes(data)
		if strings.Contains(content, "hypervisor") {
			evidence = append(evidence, vmEvidence{"CPU hypervisor flag", "VM", "hypervisor bit set in CPUID"})
		} else {
			evidence = append(evidence, vmEvidence{"CPU hypervisor flag", "clean", "no hypervisor flag"})
		}
	}

	// Check /sys/hypervisor/type (Xen, KVM)
	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		hyperType := strings.TrimSpace(string(data))
		structs.ZeroBytes(data)
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
		structs.ZeroBytes(data)
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

type vmMatcher struct {
	substr, vm string
}

func vmCheckDMIFile(path, label, cleanLevel string, matchers []vmMatcher) ([]vmEvidence, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ""
	}
	value := strings.TrimSpace(string(data))
	structs.ZeroBytes(data)
	lower := strings.ToLower(value)

	for _, m := range matchers {
		if strings.Contains(lower, m.substr) {
			var detail string
			if label != "SCSI devices" {
				detail = fmt.Sprintf("%s → %s", value, m.vm)
			} else {
				detail = m.vm + " virtual disk"
			}
			return []vmEvidence{{label, "VM", detail}}, m.vm
		}
	}
	if cleanLevel != "" {
		return []vmEvidence{{label, cleanLevel, value}}, ""
	}
	return nil, ""
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
		return ""
	default:
		return ""
	}
}

// classifyVMProcess checks if a process name indicates a VM guest agent.
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

	found := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
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
