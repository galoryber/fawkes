//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type ProcInfoCommand struct{}

func (c *ProcInfoCommand) Name() string {
	return "proc-info"
}

func (c *ProcInfoCommand) Description() string {
	return "Deep process inspection via /proc filesystem: cmdline, environment, capabilities, cgroups, fds, namespaces (T1057)"
}

type procInfoArgs struct {
	PID    int    `json:"pid"`
	Action string `json:"action"`
}

func (c *ProcInfoCommand) Execute(task structs.Task) structs.CommandResult {
	var args procInfoArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Plain text fallback: "info", "connections", "mounts", "info 1234"
			parts := strings.Fields(task.Params)
			args.Action = parts[0]
			if len(parts) > 1 {
				if pid, err := strconv.Atoi(parts[1]); err == nil {
					args.PID = pid
				}
			}
		}
	}

	if args.Action == "" {
		args.Action = "info"
	}

	switch strings.ToLower(args.Action) {
	case "info":
		if args.PID <= 0 {
			// Default to self
			args.PID = os.Getpid()
		}
		return procInfoDetail(args.PID)
	case "connections":
		return procInfoConnections()
	case "mounts":
		return procInfoMounts()
	case "modules":
		return procInfoModules()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: info, connections, mounts, modules", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// procInfoDetail gathers detailed info from /proc/<pid>/
func procInfoDetail(pid int) structs.CommandResult {
	var sb strings.Builder
	procDir := fmt.Sprintf("/proc/%d", pid)

	if _, err := os.Stat(procDir); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Process %d not found (/proc/%d does not exist)", pid, pid),
			Status:    "error",
			Completed: true,
		}
	}

	sb.WriteString(fmt.Sprintf("=== Process Info: PID %d ===\n\n", pid))

	// Command line
	if data, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		sb.WriteString(fmt.Sprintf("Command line: %s\n", strings.TrimSpace(cmdline)))
	}

	// Comm (short process name)
	if data, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		sb.WriteString(fmt.Sprintf("Process name: %s\n", strings.TrimSpace(string(data))))
	}

	// Status (contains UID, GID, capabilities, threads, memory)
	if data, err := os.ReadFile(filepath.Join(procDir, "status")); err == nil {
		sb.WriteString("\nStatus:\n")
		interestingFields := map[string]bool{
			"Uid": true, "Gid": true, "Groups": true,
			"VmSize": true, "VmRSS": true, "VmPeak": true,
			"Threads": true, "Name": true, "State": true,
			"PPid": true, "TracerPid": true, "Seccomp": true,
			"CapInh": true, "CapPrm": true, "CapEff": true, "CapBnd": true, "CapAmb": true,
			"NoNewPrivs": true,
		}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && interestingFields[strings.TrimSpace(parts[0])] {
				sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(line)))
			}
		}
	}

	// Exe (actual binary path)
	if target, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		sb.WriteString(fmt.Sprintf("\nExecutable: %s\n", target))
	}

	// CWD
	if target, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		sb.WriteString(fmt.Sprintf("Working dir: %s\n", target))
	}

	// Root (chroot detection)
	if target, err := os.Readlink(filepath.Join(procDir, "root")); err == nil {
		sb.WriteString(fmt.Sprintf("Root dir: %s", target))
		if target != "/" {
			sb.WriteString(" [!] CHROOT detected")
		}
		sb.WriteString("\n")
	}

	// Environment variables
	if data, err := os.ReadFile(filepath.Join(procDir, "environ")); err == nil {
		envVars := strings.Split(string(data), "\x00")
		sb.WriteString(fmt.Sprintf("\nEnvironment (%d vars):\n", len(envVars)-1))
		for _, v := range envVars {
			v = strings.TrimSpace(v)
			if v != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", v))
			}
		}
	} else {
		sb.WriteString("\nEnvironment: (permission denied)\n")
	}

	// Cgroups
	if data, err := os.ReadFile(filepath.Join(procDir, "cgroup")); err == nil {
		sb.WriteString("\nCgroups:\n")
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
	}

	// Namespaces
	nsDir := filepath.Join(procDir, "ns")
	if entries, err := os.ReadDir(nsDir); err == nil {
		sb.WriteString("\nNamespaces:\n")
		for _, entry := range entries {
			if target, err := os.Readlink(filepath.Join(nsDir, entry.Name())); err == nil {
				sb.WriteString(fmt.Sprintf("  %s -> %s\n", entry.Name(), target))
			}
		}
	}

	// File descriptors (count + interesting ones)
	fdDir := filepath.Join(procDir, "fd")
	if entries, err := os.ReadDir(fdDir); err == nil {
		sb.WriteString(fmt.Sprintf("\nOpen file descriptors: %d\n", len(entries)))
		// Show first 20 interesting FDs
		shown := 0
		for _, entry := range entries {
			if shown >= 20 {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(entries)-20))
				break
			}
			if target, err := os.Readlink(filepath.Join(fdDir, entry.Name())); err == nil {
				// Skip common stdin/stdout/stderr and /dev/null
				if !strings.HasPrefix(target, "pipe:") && !strings.HasPrefix(target, "anon_inode:") &&
					target != "/dev/null" && target != "/dev/pts/0" {
					sb.WriteString(fmt.Sprintf("  fd %s -> %s\n", entry.Name(), target))
					shown++
				}
			}
		}
	} else {
		sb.WriteString("\nFile descriptors: (permission denied)\n")
	}

	// Maps (memory mappings — show loaded libraries)
	if data, err := os.ReadFile(filepath.Join(procDir, "maps")); err == nil {
		libs := make(map[string]bool)
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				path := fields[len(fields)-1]
				if strings.HasPrefix(path, "/") && !libs[path] {
					libs[path] = true
				}
			}
		}
		sb.WriteString(fmt.Sprintf("\nLoaded libraries (%d):\n", len(libs)))
		for lib := range libs {
			sb.WriteString(fmt.Sprintf("  %s\n", lib))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// procInfoConnections parses /proc/net/tcp and /proc/net/tcp6 for active connections
func procInfoConnections() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Network Connections ===\n\n")

	for _, proto := range []struct {
		name string
		path string
		ipv6 bool
	}{
		{"TCP", "/proc/net/tcp", false},
		{"TCP6", "/proc/net/tcp6", true},
		{"UDP", "/proc/net/udp", false},
		{"UDP6", "/proc/net/udp6", true},
	} {
		data, err := os.ReadFile(proto.path)
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) <= 1 {
			continue
		}

		sb.WriteString(fmt.Sprintf("%s connections:\n", proto.name))
		for _, line := range lines[1:] { // Skip header
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}

			localAddr := parseHexAddr(fields[1], proto.ipv6)
			remoteAddr := parseHexAddr(fields[2], proto.ipv6)
			state := parseTCPState(fields[3])

			// Find PID from inode if possible
			inode := ""
			if len(fields) >= 10 {
				inode = fields[9]
			}
			pid := findPIDForInode(inode)

			if pid != "" {
				sb.WriteString(fmt.Sprintf("  %s -> %s  %s  PID:%s\n", localAddr, remoteAddr, state, pid))
			} else {
				sb.WriteString(fmt.Sprintf("  %s -> %s  %s\n", localAddr, remoteAddr, state))
			}
		}
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// procInfoMounts shows mount information from /proc/self/mountinfo
func procInfoMounts() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Mount Information ===\n\n")

	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading /proc/self/mounts: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			sb.WriteString(fmt.Sprintf("  %-40s %-20s %s\n", fields[1], fields[0], fields[2]))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// procInfoModules lists loaded kernel modules from /proc/modules
func procInfoModules() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Loaded Kernel Modules ===\n\n")

	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading /proc/modules: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	sb.WriteString(fmt.Sprintf("%-30s %-12s %s\n", "Module", "Size", "Used By"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			usedBy := ""
			if len(fields) >= 4 {
				usedBy = fields[3]
			}
			sb.WriteString(fmt.Sprintf("%-30s %-12s %s\n", fields[0], fields[1], usedBy))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// parseHexAddr converts a hex encoded address (e.g., "0100007F:1F90") to IP:port
func parseHexAddr(hexAddr string, ipv6 bool) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return hexAddr
	}

	port, _ := strconv.ParseInt(parts[1], 16, 64)

	if ipv6 {
		// IPv6 hex is 32 chars, grouped in 4-byte little-endian words
		if len(parts[0]) != 32 {
			return fmt.Sprintf("[%s]:%d", parts[0], port)
		}
		// Simplify — just show condensed form
		ip := parseIPv6Hex(parts[0])
		return fmt.Sprintf("[%s]:%d", ip, port)
	}

	// IPv4: hex is little-endian
	if len(parts[0]) != 8 {
		return fmt.Sprintf("%s:%d", parts[0], port)
	}
	b0, _ := strconv.ParseInt(parts[0][6:8], 16, 64)
	b1, _ := strconv.ParseInt(parts[0][4:6], 16, 64)
	b2, _ := strconv.ParseInt(parts[0][2:4], 16, 64)
	b3, _ := strconv.ParseInt(parts[0][0:2], 16, 64)

	return fmt.Sprintf("%d.%d.%d.%d:%d", b0, b1, b2, b3, port)
}

// parseIPv6Hex converts 32-char hex to IPv6 string
func parseIPv6Hex(hex string) string {
	if len(hex) != 32 {
		return hex
	}
	// Each 8-char group is a 32-bit word in little-endian
	var parts []string
	for i := 0; i < 32; i += 8 {
		word := hex[i : i+8]
		// Reverse byte order within the 4-byte word
		b0 := word[6:8]
		b1 := word[4:6]
		b2 := word[2:4]
		b3 := word[0:2]
		parts = append(parts, b0+b1)
		parts = append(parts, b2+b3)
	}
	return strings.Join(parts, ":")
}

// parseTCPState converts hex state to human-readable
func parseTCPState(hexState string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hexState)]; ok {
		return s
	}
	return hexState
}

// findPIDForInode tries to map a socket inode to a PID
func findPIDForInode(inode string) string {
	if inode == "" || inode == "0" {
		return ""
	}

	socketLink := fmt.Sprintf("socket:[%s]", inode)
	procDir := "/proc"

	entries, err := os.ReadDir(procDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only check numeric dirs (PIDs)
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		fdDir := filepath.Join(procDir, pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if target == socketLink {
				// Get process name
				comm := pid
				if data, err := os.ReadFile(filepath.Join(procDir, pid, "comm")); err == nil {
					comm = fmt.Sprintf("%s(%s)", pid, strings.TrimSpace(string(data)))
				}
				return comm
			}
		}
	}

	return ""
}
