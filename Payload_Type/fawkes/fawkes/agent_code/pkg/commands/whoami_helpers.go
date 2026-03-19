package commands

import (
	"fmt"
	"strconv"
	"strings"
)

// linuxCapNames maps capability bit positions to names.
var linuxCapNames = [...]string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
	"CAP_PERFMON",
	"CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// parseLinuxCapabilities converts a hex capability bitmask (from /proc/self/status)
// to a list of human-readable capability names. Returns nil if no capabilities are set.
func parseLinuxCapabilities(hexStr string) []string {
	hexStr = strings.TrimSpace(hexStr)
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return nil
	}
	if val == 0 {
		return nil
	}

	var caps []string
	for i := 0; i < len(linuxCapNames); i++ {
		if val&(1<<uint(i)) != 0 {
			caps = append(caps, linuxCapNames[i])
		}
	}

	// Check for unknown high bits
	known := uint64((1 << len(linuxCapNames)) - 1)
	if val & ^known != 0 {
		caps = append(caps, fmt.Sprintf("UNKNOWN(0x%x)", val & ^known))
	}

	return caps
}

// isFullCapabilities returns true if the capability hex string represents
// all capabilities set (root-equivalent). Checks if all known cap bits are set.
func isFullCapabilities(hexStr string) bool {
	hexStr = strings.TrimSpace(hexStr)
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return false
	}
	allKnown := uint64((1 << len(linuxCapNames)) - 1)
	return val&allKnown == allKnown
}
