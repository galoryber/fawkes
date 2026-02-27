+++
title = "security-info"
chapter = false
weight = 214
hidden = false
+++

## Summary

Report security posture and active security controls. Provides a consolidated view of what security mechanisms are enabled on the target, helping operators understand defensive capabilities and plan evasion strategies.

## Arguments

No arguments required.

## Usage

```
security-info
```

## Platform Details

### Linux
| Control | Detection Method |
|---------|-----------------|
| SELinux | `getenforce` command |
| AppArmor | `aa-status` or `/sys/module/apparmor/parameters/enabled` |
| Seccomp | `/proc/self/status` Seccomp field |
| Linux Audit (auditd) | `auditctl -s` |
| iptables | `iptables -L -n` rule count |
| nftables | `nft list ruleset` |
| ASLR | `/proc/sys/kernel/randomize_va_space` |
| Kernel Lockdown | `/sys/kernel/security/lockdown` |
| YAMA ptrace | `/proc/sys/kernel/yama/ptrace_scope` |

### macOS
| Control | Detection Method |
|---------|-----------------|
| SIP (System Integrity Protection) | `csrutil status` |
| Gatekeeper | `spctl --status` |
| FileVault | `fdesetup status` |
| macOS Firewall | `com.apple.alf` plist |
| XProtect | `system_profiler` |

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

- Linux: Runs `getenforce`, `aa-status`, `auditctl`, `iptables`, `nft` — some require root for full results
- macOS: Runs `csrutil`, `spctl`, `fdesetup`, `system_profiler` — standard utility commands
- Windows: Spawns `powershell.exe` for WMI/registry queries — may trigger command-line logging
- Passive reconnaissance — does not modify any security settings

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
- **T1518.001** — Software Discovery: Security Software Discovery
