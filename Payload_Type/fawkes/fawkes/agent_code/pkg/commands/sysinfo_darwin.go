//go:build darwin

package commands

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func collectPlatformSysinfo(sb *strings.Builder) {
	sb.WriteString("--- macOS Details ---\n")

	// OS version from SystemVersion.plist (replaces sw_vers child process)
	if data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist"); err == nil {
		ver := parseSystemVersionPlist(string(data))
		if ver.ProductName != "" {
			sb.WriteString(fmt.Sprintf("Product:       %s\n", ver.ProductName))
		}
		if ver.ProductVersion != "" {
			sb.WriteString(fmt.Sprintf("Version:       %s\n", ver.ProductVersion))
		}
		if ver.ProductBuildVersion != "" {
			sb.WriteString(fmt.Sprintf("Build:         %s\n", ver.ProductBuildVersion))
		}
	}

	// Kernel version via syscall (replaces uname -r)
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err == nil {
		release := unix.ByteSliceToString(utsname.Release[:])
		sb.WriteString(fmt.Sprintf("Kernel:        %s\n", release))
	}

	// Hardware model via sysctl (replaces sysctl -n hw.model)
	if model, err := unix.Sysctl("hw.model"); err == nil {
		sb.WriteString(fmt.Sprintf("Model:         %s\n", model))
	}

	// Serial number — no native API, must use ioreg
	if out, err := execCmdTimeoutOutput("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		if serial := parseIoregSerial(string(out)); serial != "" {
			sb.WriteString(fmt.Sprintf("Serial:        %s\n", serial))
		}
	}

	// CPU brand string via sysctl (replaces sysctl -n machdep.cpu.brand_string)
	cpuBrand := ""
	if brand, err := unix.Sysctl("machdep.cpu.brand_string"); err == nil {
		cpuBrand = brand
		sb.WriteString(fmt.Sprintf("CPU:           %s\n", brand))
	}

	// Apple Silicon / Rosetta 2 detection via sysctl (replaces 2 sysctl child processes)
	procTranslated := ""
	if val, err := unix.Sysctl("sysctl.proc_translated"); err == nil {
		procTranslated = val
	}
	isAppleSilicon, isRosetta := parseRosettaStatus(procTranslated, cpuBrand)
	if isAppleSilicon {
		sb.WriteString("Chip:          Apple Silicon\n")
	}
	if isRosetta {
		sb.WriteString("Rosetta 2:     active (translated process)\n")
	}
	sb.WriteString(fmt.Sprintf("Arch:          %s\n", runtime.GOARCH))

	// Memory via sysctl (replaces sysctl -n hw.memsize)
	if memBytes, err := unix.SysctlUint64("hw.memsize"); err == nil {
		sb.WriteString(fmt.Sprintf("Total Memory:  %s\n", formatFileSize(int64(memBytes))))
	}

	// Uptime via sysctl (replaces sysctl -n kern.boottime)
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		bootTime := time.Unix(tv.Sec, 0)
		uptime := time.Since(bootTime)
		days := int(uptime.Hours()) / 24
		hours := int(uptime.Hours()) % 24
		minutes := int(uptime.Minutes()) % 60
		sb.WriteString(fmt.Sprintf("Uptime:        %dd %dh %dm\n", days, hours, minutes))
		sb.WriteString(fmt.Sprintf("Boot Time:     %s\n", bootTime.Format("2006-01-02 15:04:05")))
	}

	// User info
	sb.WriteString(fmt.Sprintf("UID:           %d\n", os.Getuid()))
	sb.WriteString(fmt.Sprintf("EUID:          %d\n", os.Geteuid()))

	sb.WriteString("\n--- Security Status ---\n")

	// SIP status — no native API, must use csrutil
	if out, err := execCmdTimeoutOutput("csrutil", "status"); err == nil {
		status := strings.TrimSpace(string(out))
		if strings.Contains(status, "enabled") {
			sb.WriteString("SIP:           enabled\n")
		} else if strings.Contains(status, "disabled") {
			sb.WriteString("SIP:           disabled\n")
		}
	}

	// Gatekeeper status — no native API, must use spctl
	if out, err := execCmdTimeout("spctl", "--status"); err == nil {
		gk := parseSpctlStatus(string(out))
		sb.WriteString(fmt.Sprintf("Gatekeeper:    %s\n", gk))
	}

	// FileVault status — no native API, must use fdesetup
	if out, err := execCmdTimeout("fdesetup", "status"); err == nil {
		fv := parseFdesetupStatus(string(out))
		sb.WriteString(fmt.Sprintf("FileVault:     %s\n", fv))
	}

	// MDM enrollment — no native API, must use profiles
	if out, err := execCmdTimeout("profiles", "status", "-type", "enrollment"); err == nil {
		mdm := parseMDMEnrollment(string(out))
		if mdm.Enrolled {
			sb.WriteString("MDM Enrolled:  yes\n")
			if mdm.DEPEnrolled {
				sb.WriteString("DEP Enrolled:  yes\n")
			}
		} else {
			sb.WriteString("MDM Enrolled:  no\n")
		}
	}
}
