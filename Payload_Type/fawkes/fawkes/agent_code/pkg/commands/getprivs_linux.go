//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type GetPrivsCommand struct{}

func (c *GetPrivsCommand) Name() string {
	return "getprivs"
}

func (c *GetPrivsCommand) Description() string {
	return "List process capabilities and security context"
}

func (c *GetPrivsCommand) Execute(task structs.Task) structs.CommandResult {
	var params getPrivsParams
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
			params.Action = "list"
		}
	}
	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return listLinuxPrivileges()
	case "enable", "disable", "strip":
		return errorf("Action '%s' is not supported on Linux (use Windows for token privilege manipulation)", params.Action)
	default:
		return errorf("Unknown action: %s (use 'list')", params.Action)
	}
}

func listLinuxPrivileges() structs.CommandResult {
	identity := fmt.Sprintf("uid=%d euid=%d gid=%d egid=%d",
		os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())

	u, err := user.Current()
	if err == nil {
		identity = fmt.Sprintf("%s (%s)", u.Username, identity)
	}

	source := "process"
	if os.Geteuid() == 0 {
		source = "root"
	}

	// Parse capabilities from /proc/self/status
	caps := parseCapabilities()

	// Decode effective capabilities into entries
	var entries []privOutputEntry
	if capEff, ok := caps["CapEff"]; ok {
		entries = decodeCapabilities(capEff, "CapEff")
	}

	// Add permitted capabilities that aren't effective
	if capPrm, ok := caps["CapPrm"]; ok {
		permitted := decodeCapabilities(capPrm, "CapPrm")
		effSet := make(map[string]bool)
		for _, e := range entries {
			effSet[e.Name] = true
		}
		for _, p := range permitted {
			if !effSet[p.Name] {
				entries = append(entries, privOutputEntry{
					Name:        p.Name,
					Status:      "Permitted (not effective)",
					Description: p.Description,
				})
			}
		}
	}

	// Integrity approximation
	integrity := "Standard"
	if os.Geteuid() == 0 {
		integrity = "Root"
	}

	// Check security modules
	securityContext := getSecurityContext()
	if securityContext != "" {
		integrity += " | " + securityContext
	}

	output := privsOutput{
		Identity:   identity,
		Source:     source,
		Integrity:  integrity,
		Privileges: entries,
	}

	data, err := json.Marshal(output)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(data))
}

// parseCapabilities reads capability sets from /proc/self/status
func parseCapabilities() map[string]uint64 {
	caps := make(map[string]uint64)
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return caps
	}

	for _, line := range strings.Split(string(data), "\n") {
		for _, prefix := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			if strings.HasPrefix(line, prefix+":") {
				hexStr := strings.TrimSpace(strings.TrimPrefix(line, prefix+":"))
				val, err := strconv.ParseUint(hexStr, 16, 64)
				if err == nil {
					caps[prefix] = val
				}
			}
		}
	}
	return caps
}

// decodeCapabilities converts a capability bitmask into named entries.
// Reuses capNames from privesc_check.go (same package, same build tag).
func decodeCapabilities(bitmask uint64, setName string) []privOutputEntry {
	var entries []privOutputEntry
	for i := 0; i < len(capNames); i++ {
		if bitmask&(1<<uint(i)) != 0 {
			name := capNames[i]
			if name == "" {
				name = fmt.Sprintf("cap_%d", i)
			}
			entries = append(entries, privOutputEntry{
				Name:        strings.ToUpper(name),
				Status:      "Enabled",
				Description: capDescription(name),
			})
		}
	}
	return entries
}

// getSecurityContext returns SELinux or AppArmor context if available
func getSecurityContext() string {
	// SELinux
	if data, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		ctx := strings.TrimSpace(string(data))
		if ctx != "" && ctx != "unconfined" {
			return "SELinux: " + ctx
		}
	}

	// AppArmor
	if data, err := os.ReadFile("/proc/self/attr/apparmor/current"); err == nil {
		ctx := strings.TrimSpace(string(data))
		if ctx != "" && ctx != "unconfined" {
			return "AppArmor: " + ctx
		}
	}

	// Check LSM from /sys/kernel/security/lsm
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsm := strings.TrimSpace(string(data))
		if lsm != "" {
			return "LSM: " + lsm
		}
	}

	return ""
}

// capDescription returns a human-readable description for a Linux capability
func capDescription(name string) string {
	descs := map[string]string{
		"cap_chown":              "Change file ownership",
		"cap_dac_override":       "Override file read/write/execute permission",
		"cap_dac_read_search":    "Override file read permission and directory",
		"cap_fowner":             "Override ownership checks on file operations",
		"cap_fsetid":             "Don't clear set-user/group-ID on file modify",
		"cap_kill":               "Send signals to any process",
		"cap_setgid":             "Set any group ID",
		"cap_setuid":             "Set any user ID",
		"cap_setpcap":            "Transfer capabilities between processes",
		"cap_linux_immutable":    "Set immutable and append-only file flags",
		"cap_net_bind_service":   "Bind to ports below 1024",
		"cap_net_broadcast":      "Network broadcasting",
		"cap_net_admin":          "Network administration (interfaces, routing)",
		"cap_net_raw":            "Use raw and packet sockets",
		"cap_ipc_lock":           "Lock memory (mlock, mlockall)",
		"cap_ipc_owner":          "Override IPC ownership checks",
		"cap_sys_module":         "Load/unload kernel modules",
		"cap_sys_rawio":          "Perform I/O port operations (iopl, ioperm)",
		"cap_sys_chroot":         "Use chroot",
		"cap_sys_ptrace":         "Trace and inspect any process (ptrace)",
		"cap_sys_pacct":          "Configure process accounting",
		"cap_sys_admin":          "System administration (mount, sethostname, etc)",
		"cap_sys_boot":           "Reboot the system",
		"cap_sys_nice":           "Set process scheduling priority",
		"cap_sys_resource":       "Override resource limits",
		"cap_sys_time":           "Set the system clock",
		"cap_sys_tty_config":     "Configure TTY devices",
		"cap_mknod":              "Create special files (mknod)",
		"cap_lease":              "Establish file leases",
		"cap_audit_write":        "Write to audit log",
		"cap_audit_control":      "Configure audit subsystem",
		"cap_setfcap":            "Set file capabilities",
		"cap_mac_override":       "Override MAC (SELinux/Smack) restrictions",
		"cap_mac_admin":          "Administer MAC configuration",
		"cap_syslog":             "Perform syslog operations",
		"cap_wake_alarm":         "Trigger system wakeup",
		"cap_block_suspend":      "Block system suspend",
		"cap_audit_read":         "Read audit log via multicast",
		"cap_perfmon":            "Performance monitoring (perf_event_open)",
		"cap_bpf":                "BPF operations",
		"cap_checkpoint_restore": "Checkpoint/restore operations",
	}
	if desc, ok := descs[name]; ok {
		return desc
	}
	return ""
}
