+++
title = "vm-detect"
chapter = false
weight = 212
hidden = false
+++

## Summary

Detect virtual machine and hypervisor environment, or perform sandbox evasion analysis with scored checks. Two modes:

- **detect** (default): Identifies VMware, VirtualBox, Hyper-V, QEMU/KVM, Xen, Parallels, and cloud providers (AWS EC2, GCP) through MAC address OUI, DMI/SMBIOS, VM tools/files, SCSI devices, CPU hypervisor flags, and guest agent processes.
- **sandbox**: Advanced sandbox/analysis evasion checks with a 0-100 risk score. Checks CPU count, RAM, disk size, system uptime, sleep timing accuracy, hostname patterns, process count, and username. Returns structured JSON with per-check scores and an overall verdict (clean/suspicious/likely_sandbox/sandbox).

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | No | `detect` (VM detection) or `sandbox` (sandbox evasion analysis). Default: `detect` |

## Usage

### VM/hypervisor detection
```
vm-detect
vm-detect -action detect
```

### Sandbox evasion analysis
```
vm-detect -action sandbox
```

## Sandbox Checks

| Check | Category | Suspicious Threshold | Max Score |
|-------|----------|---------------------|-----------|
| CPU Count | hardware | < 2 CPUs | 15 |
| Total RAM | hardware | < 2 GB | 15 |
| Disk Size | hardware | < 50 GB | 15 |
| System Uptime | timing | < 5 minutes | 15 |
| Sleep Timing | timing | Sleep fast-forwarded | 20 |
| Hostname | environment | Sandbox-like patterns | 10 |
| Process Count | environment | < 50 processes | 15 |
| Username | environment | Default/generic names | 10 |

**Verdict thresholds:** 0-19 = clean, 20-44 = suspicious, 45-69 = likely_sandbox, 70-100 = sandbox

## Platform Details

### Cross-platform (detect mode)
- MAC address check against known VM OUI prefixes (VMware, VirtualBox, Hyper-V, Xen, QEMU/KVM, OpenStack)

### Linux
- DMI product_name, sys_vendor, bios_vendor, board_name
- SCSI device names, CPU hypervisor flag, hypervisor type
- Guest agent process scan (vmtoolsd, VBoxService, qemu-ga, etc.)
- Sandbox: /proc/uptime, /proc/meminfo, statfs for disk

### Windows
- VM files/directories, VM driver files, Hyper-V bus driver
- Sandbox: GetTickCount64, GlobalMemoryStatusEx, GetDiskFreeSpaceExW, CreateToolhelp32Snapshot

### macOS
- VM tools and kernel extensions
- Sandbox: kern.boottime, hw.memsize, statfs

## OPSEC Considerations

- All checks are passive (filesystem reads, network interface enumeration, timing)
- No registry queries, WMI calls, or CPUID instructions that could trigger sandbox detectors
- Sleep timing check introduces a 500ms delay

## MITRE ATT&CK Mapping

- **T1497** — Virtualization/Sandbox Evasion
- **T1497.001** — Virtualization/Sandbox Evasion: System Checks
