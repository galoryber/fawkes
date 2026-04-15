+++
title = "security-info"
chapter = false
weight = 214
hidden = false
+++

## Summary

Report security posture and active security controls, or detect installed EDR/XDR/AV products. Provides a consolidated view of defensive capabilities on the target, helping operators understand what they're up against.

## Actions

| Action | Description |
|--------|-------------|
| `all` | Report security posture and active controls (default) |
| `edr` | Detect installed EDR/XDR/AV products from 20+ vendors via process enumeration and filesystem path checks |

### Arguments

#### Action
Choose `all` (default) to report full security posture, or `edr` to detect installed endpoint security products.

## Usage

```
security-info
security-info -action all
security-info -action edr
```

## EDR Detection

The `edr` action checks for 20+ endpoint security products:

| Vendor | Product |
|--------|---------|
| CrowdStrike | Falcon |
| SentinelOne | SentinelOne Agent |
| VMware | Carbon Black |
| Microsoft | Defender/ATP |
| Palo Alto | Cortex XDR |
| BlackBerry | Cylance |
| Sophos | Sophos AV/Intercept X |
| ESET | ESET Endpoint |
| Kaspersky | KESL/KAV |
| Trend Micro | Deep Security Agent |
| Broadcom | Symantec Endpoint |
| Trellix | McAfee ENS |
| Elastic | Elastic Agent/Endpoint |
| Wazuh | Wazuh OSSEC |
| osquery | osqueryd |
| Tanium | Tanium Client |
| Qualys | Cloud Agent |
| Rapid7 | InsightAgent |
| Fortinet | Lacework |
| Huntress | Huntress Agent |

Detection methods:
- **Process scan**: Matches running processes against known EDR process names
- **Path check**: Checks common install directories when processes aren't running
- **Windows WMI**: Queries SecurityCenter2 for registered AV products

Output includes JSON with product name, vendor, status (running/installed), PID, and path.

## Platform Details

### Linux
| Control | Detection Method |
|---------|-----------------|
| SELinux | `/sys/fs/selinux/enforce` (native), `getenforce` fallback |
| AppArmor | `/sys/module/apparmor/parameters/enabled` (native), `aa-status` fallback |
| Seccomp | `/proc/self/status` Seccomp field |
| Linux Audit (auditd) | `/proc/self/loginuid` + `/var/run/auditd.pid` (native) |
| iptables | `iptables -L -n` rule count |
| nftables | `nft list ruleset` |
| ASLR | `/proc/sys/kernel/randomize_va_space` |
| Kernel Lockdown | `/sys/kernel/security/lockdown` |
| YAMA ptrace | `/proc/sys/kernel/yama/ptrace_scope` |
| LSM Stack | `/sys/kernel/security/lsm` (Landlock, BPF LSM, TOMOYO) |
| Unprivileged BPF | `/proc/sys/kernel/unprivileged_bpf_disabled` |
| kptr_restrict | `/proc/sys/kernel/kptr_restrict` |
| dmesg_restrict | `/proc/sys/kernel/dmesg_restrict` |
| dm-crypt/LUKS | `/dev/mapper/` encrypted device enumeration |

### macOS
| Control | Detection Method |
|---------|-----------------|
| SIP (System Integrity Protection) | `csrutil status` |
| Gatekeeper | `spctl --status` |
| FileVault | `fdesetup status` |
| macOS Firewall | `com.apple.alf` plist |
| XProtect | XProtect.bundle file stat (native) |
| Configuration Profiles | `/var/db/ConfigurationProfiles/` directory scan (native) |
| MDM Enrollment | `.profilesAreInstalled` indicator file (native) |
| Remote Login (SSH) | `/etc/ssh/sshd_config` parsing (native) |
| TCC System DB | `/Library/Application Support/com.apple.TCC/TCC.db` readability probe (native) |
| JAMF (Casper) | `/usr/local/jamf/bin/jamf` file stat (native) |
| Apple Remote Desktop | ARDAgent.app + plist detection (native) |

### Windows
| Control | Detection Method |
|---------|-----------------|
| Windows Defender RT | `Get-MpComputerStatus` |
| AMSI | Default enabled on Windows 10+ |
| Credential Guard | WMI DeviceGuard class |
| UAC | Registry `EnableLUA` |
| Windows Firewall | `Get-NetFirewallProfile` |
| BitLocker | `Get-BitLockerVolume` |
| PS Constrained Language Mode | `LanguageMode` property |

## OPSEC Considerations

- Linux: Most checks use native sysfs/procfs reads (zero subprocess overhead). `iptables`/`nft` require subprocess
- macOS: `csrutil`, `spctl`, `fdesetup` require subprocess; other checks use native file reads
- Windows: Spawns `powershell.exe` for WMI/registry queries — may trigger command-line logging
- EDR action: Process enumeration and path checks are passive — no subprocess spawned on Linux/macOS
- Passive reconnaissance — does not modify any security settings

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
- **T1518.001** — Software Discovery: Security Software Discovery
