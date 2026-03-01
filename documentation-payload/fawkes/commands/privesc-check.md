+++
title = "privesc-check"
chapter = false
weight = 100
hidden = false
+++

## Summary

Cross-platform privilege escalation enumeration. Scans for common privilege escalation vectors with platform-specific checks for Windows, Linux, and macOS.

- **Windows:** Token privileges (potato attacks, SeDebug, SeBackup), unquoted service paths, modifiable service binaries, AlwaysInstallElevated, auto-logon credentials, UAC configuration, LSA protection, writable PATH directories, unattended install files
- **Linux:** SUID/SGID binaries, file capabilities, sudo rules, writable paths, containers
- **macOS:** LaunchDaemons/Agents, TCC database, dylib hijacking, SIP status

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | all | Check to perform (see platform-specific actions below) |

### Shared Actions (All Platforms)

- **all** — Run all platform-appropriate checks
- **writable** — Find writable PATH directories and sensitive files/paths

### Windows-Only Actions

- **privileges** — Enumerate token privileges, flag exploitable ones (SeImpersonate, SeDebug, SeBackup, etc.) with exploitation guidance
- **services** — Check for unquoted service paths, modifiable service binaries, and writable binary directories
- **registry** — Check AlwaysInstallElevated, auto-logon credentials, LSA protection (RunAsPPL), Credential Guard, WSUS configuration
- **uac** — Report UAC configuration (EnableLUA, ConsentPromptBehavior, Secure Desktop, FilterAdminToken)
- **unattend** — Search for unattended install files (sysprep/Unattend.xml) and other credential-containing files

### Linux-Only Actions

- **suid** — Find SUID/SGID binaries, flag exploitable ones (find, python, docker, etc.)
- **sudo** — Check `sudo -l` (non-interactive), read `/etc/sudoers` if accessible
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
privesc-check -action privileges
privesc-check -action services
privesc-check -action registry
privesc-check -action uac
privesc-check -action suid
privesc-check -action launchdaemons
```

### Example Output (Windows, all)

```
=== WINDOWS PRIVILEGE ESCALATION CHECK ===

--- Token Privileges ---
Token privileges (23 total):
  SeIncreaseQuotaPrivilege               [Disabled]
  SeSecurityPrivilege                    [Disabled]
  SeBackupPrivilege                      [Disabled]
  SeImpersonatePrivilege                 [Enabled]
  ...

[!] EXPLOITABLE privileges (3):
  [!] SeImpersonatePrivilege              [Enabled]  → Potato attacks (JuicyPotato, PrintSpoofer, GodPotato) → SYSTEM
  [*] SeBackupPrivilege                   [Disabled] → Read any file (SAM, SYSTEM hives, NTDS.dit)
  [!] SeDebugPrivilege                    [Enabled]  → Inject into/dump any process including LSASS

Note: Disabled privileges can be enabled with 'getprivs -action enable -privilege <name>'

Integrity Level: High (S-1-16-12288) (elevated admin)

--- UAC Configuration ---
UAC is enabled (EnableLUA = 1)
Admin consent prompt behavior: Prompt for consent for non-Windows binaries (5) — DEFAULT
[*] Standard config — UAC bypass via auto-elevating binaries possible (fodhelper, computerdefaults, sdclt)

--- Service Misconfigurations ---
Checked 247 services:

Unquoted service paths (2):
  VulnerableService
    Path: C:\Program Files\Vulnerable App\service.exe -start
    Start: Auto
[!] Unquoted paths with spaces allow binary planting in intermediate directories

--- Registry Checks ---
AlwaysInstallElevated:
  Not enabled (safe)

Auto-Logon Credentials:
  Not configured

LSA Protection:
  [!] LSA Protection (RunAsPPL) is NOT enabled — LSASS can be dumped
```

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1548 | Abuse Elevation Control Mechanism |
| T1548.001 | Setuid and Setgid |
| T1548.002 | Bypass User Account Control |
| T1574.009 | Path Interception by Unquoted Path |
| T1552.001 | Unsecured Credentials: Credentials In Files |
| T1613 | Container and Resource Discovery |
| T1082 | System Information Discovery |
