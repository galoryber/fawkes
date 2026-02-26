+++
title = "sysinfo"
chapter = false
weight = 123
hidden = false
+++

## Summary

Collect comprehensive system information in a single command. Essential for initial enumeration — provides OS version, hardware details, memory, uptime, domain membership, security configuration, and more.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

No arguments required.

## Usage

### Collect system information
```
sysinfo
```

## Output

### Common Fields (all platforms)
- Hostname, OS, Architecture, CPU count
- Process ID (PID) and parent PID
- Working directory, current time, timezone

### Windows-Specific
- Product name, version (e.g., 25H2), build number
- FQDN and domain membership
- Total/available memory with usage percentage
- System uptime and boot time
- Elevation status (admin/non-admin)
- .NET Framework version

### Linux-Specific
- Distribution name and version (from /etc/os-release)
- Kernel version
- Total/available memory
- System uptime and boot time
- UID/EUID/GID (detect privilege level)
- SELinux enforcement status
- Hardware/virtualization detection (DMI product name, hypervisor type)

### macOS-Specific
- Product name, version, build (from sw_vers)
- Kernel version, hardware model
- Total memory
- System uptime and boot time
- UID/EUID
- System Integrity Protection (SIP) status

## OPSEC Considerations

- Read-only enumeration — no disk writes or system modifications
- Uses standard APIs and /proc filesystem on Linux
- macOS implementation calls sw_vers, uname, sysctl, csrutil — brief subprocess activity
- Windows reads registry and calls memory/system APIs — minimal footprint

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
