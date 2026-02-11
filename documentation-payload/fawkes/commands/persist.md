+++
title = "persist"
chapter = false
weight = 125
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Install or remove persistence mechanisms on a Windows host. Supports registry Run key persistence and startup folder persistence, with a `list` action to enumerate existing entries.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| method | choose_one | Yes | registry | Persistence method: `registry`, `startup-folder`, or `list` |
| action | choose_one | No | install | `install` to add persistence, `remove` to delete it |
| name | string | No* | - | Registry value name or startup folder filename (*required for registry, defaults to exe name for startup) |
| path | string | No | Current agent | Path to executable. Defaults to the running agent binary. |
| hive | choose_one | No | HKCU | `HKCU` (current user, no admin needed) or `HKLM` (all users, admin required) |

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

### List Existing Persistence

Enumerate registry Run keys (HKCU + HKLM) and Startup folder contents:
```
persist -method list
```

### Example Output (list)
```
=== Persistence Entries ===

--- HKCU\Software\Microsoft\Windows\CurrentVersion\Run ---
  SecurityHealthSystray = "C:\Windows\System32\SecurityHealthSystray.exe"
  WindowsUpdate = C:\Users\setup\payload.exe

--- HKLM\Software\Microsoft\Windows\CurrentVersion\Run ---
  VMware User Process = "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

--- Startup Folder: C:\Users\setup\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup ---
  (empty)
```

## MITRE ATT&CK Mapping

- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification
