+++
title = "vm-detect"
chapter = false
weight = 212
hidden = false
+++

## Summary

Detect virtual machine and hypervisor environment. Identifies VMware, VirtualBox, Hyper-V, QEMU/KVM, Xen, Parallels, and cloud providers (AWS EC2, GCP) through multiple detection methods: MAC address OUI prefixes, DMI/SMBIOS information, VM tools/files, SCSI device names, CPU hypervisor flags, guest agent process scanning, and cloud provider board names.

Understanding the execution environment helps determine which techniques apply, whether sandbox evasion is needed, and what hardware-specific artifacts to expect.

## Arguments

No arguments required.

## Usage

```
vm-detect
```

## Platform Details

### Cross-platform
- MAC address check against known VM OUI prefixes (VMware, VirtualBox, Hyper-V, Xen, QEMU/KVM, OpenStack)

### Linux
- DMI product_name (`/sys/class/dmi/id/product_name`)
- DMI sys_vendor (`/sys/class/dmi/id/sys_vendor`)
- DMI bios_vendor (`/sys/class/dmi/id/bios_vendor`)
- DMI board_name (`/sys/class/dmi/id/board_name`) — detects GCP Compute Engine, AWS EC2
- SCSI device names (`/proc/scsi/scsi`)
- CPU hypervisor flag (`/proc/cpuinfo`)
- Hypervisor type (`/sys/hypervisor/type`) — definitive Xen/KVM detection
- Guest agent process scan (`/proc/*/comm`) — detects vmtoolsd, VBoxService, qemu-ga, hv_kvp_daemon, xe-daemon, spice-vdagent, prl_tools_service

### Windows
- VM-specific files and directories (VMware Tools, VirtualBox Guest Additions, Parallels Tools)
- VM driver files (vmhgfs.sys, vmci.sys, VBoxMouse.sys)
- Hyper-V bus driver (VMBusHID.sys)

### macOS
- VM tools and kernel extensions (VMware Tools, VBoxGuest.kext, ParallelsVmm.kext)

## OPSEC Considerations

- All checks are passive (filesystem reads, network interface enumeration, /proc scanning)
- Process scan reads `/proc/*/comm` which is lightweight and doesn't trigger process creation
- No registry queries, WMI calls, or CPUID instructions that could trigger sandbox detectors
- Safe to run in sandbox analysis environments

## MITRE ATT&CK Mapping

- **T1497.001** — Virtualization/Sandbox Evasion: System Checks
