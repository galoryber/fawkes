+++
title = "privesc-check"
chapter = false
weight = 100
hidden = false
+++

## Summary

Privilege escalation enumeration for Linux and macOS. Scans for common privilege escalation vectors including SUID/SGID binaries, sudo rules, writable paths, and platform-specific checks.

- **Linux:** capabilities, containers
- **macOS:** LaunchDaemons/Agents, TCC database, dylib hijacking, SIP status

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | all | Check to perform (see platform-specific actions below) |

### Shared Actions (Linux + macOS)

- **all** — Run all platform-appropriate checks
- **suid** — Find SUID/SGID binaries, flag exploitable ones (find, python, docker, etc.)
- **sudo** — Check `sudo -l` (non-interactive), read `/etc/sudoers` if accessible
- **writable** — Find writable PATH directories, writable sensitive files/paths

### Linux-Only Actions

- **capabilities** — Enumerate file capabilities via `getcap` and current process capabilities
- **container** — Detect Docker, Kubernetes, LXC, overlay FS, container cgroups

### macOS-Only Actions

- **launchdaemons** — Check for writable LaunchDaemons/LaunchAgents plists (persistence + privesc)
- **tcc** — Inspect TCC database for granted permissions (Full Disk Access, Accessibility, etc.)
- **dylib** — Check DYLD_* environment variables, Hardened Runtime status, writable library paths
- **sip** — Check System Integrity Protection and Authenticated Root status

## Usage

```
privesc-check -action all
privesc-check -action suid
privesc-check -action launchdaemons
privesc-check -action tcc
```

### Example Output (macOS, all)

```
=== macOS PRIVILEGE ESCALATION CHECK ===

--- SIP Status ---
System Integrity Protection status: enabled.
[*] SIP is enabled — standard protections active

--- SUID/SGID Binaries ---
SUID binaries (12 found):
  /usr/bin/sudo (-rwsr-xr-x, 378848 bytes)
  /usr/bin/passwd (-rwsr-xr-x, 68624 bytes)
  ...

--- LaunchDaemons / LaunchAgents ---
/Library/LaunchDaemons (System LaunchDaemons (run as root), 8 plists):
/Library/LaunchAgents (System LaunchAgents (run as logged-in users), 3 plists):

--- TCC Database ---
User TCC: ~/Library/Application Support/com.apple.TCC/TCC.db
  kTCCServiceAccessibility → com.example.app (auth=2) [!] Accessibility
  kTCCServiceSystemPolicyAllFiles → com.backup.app (auth=2) [!] Full Disk Access

--- Dylib Hijacking ---
  /usr/bin/ssh: Hardened Runtime (DYLD injection blocked)
[!] /usr/local/lib is WRITABLE — dylib planting possible
```

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1548 | Abuse Elevation Control Mechanism |
| T1548.001 | Setuid and Setgid |
| T1613 | Container and Resource Discovery |
| T1082 | System Information Discovery |
