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

- Linux: Most checks use native sysfs/procfs reads (zero subprocess overhead). Falls back to `getenforce`, `aa-status` when native files are unavailable. `iptables`/`nft` require subprocess for firewall rules — some require root for full results
- macOS: Runs `csrutil`, `spctl`, `fdesetup`, `system_profiler` — standard utility commands
- Windows: Spawns `powershell.exe` for WMI/registry queries — may trigger command-line logging
- Passive reconnaissance — does not modify any security settings

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
- **T1518.001** — Software Discovery: Security Software Discovery
