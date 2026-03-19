+++
title = "service"
chapter = false
weight = 46
hidden = false
+++

## Summary

Manage system services — Windows via SCM API, Linux via systemctl, macOS via launchctl. Query, start, stop, create, delete, list, enable, or disable services.

- **Windows:** Uses Win32 Service Control Manager API (OpenSCManager, CreateService, etc.). No subprocess creation — all operations run in-process via `golang.org/x/sys/windows/svc/mgr`.
- **Linux:** Uses systemctl for service management. List and query enrich output with unit file state and service details.
- **macOS:** Uses launchctl for LaunchDaemon/LaunchAgent management. Query shows `launchctl print` output and plist file contents. List parses `launchctl list` output.

{{% notice info %}}Windows, Linux, and macOS{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Action to perform: `query`, `start`, `stop`, `create`, `delete`, `list`, `enable`, `disable` |
| name | Conditional | Service name (required for all actions except `list`) |
| binpath | Conditional | Path to service binary (required for `create`, Windows only) |
| display | No | Display name for the service (for `create`, Windows only) |
| start | No | Start type: `demand` (manual), `auto` (automatic), `disabled` (default: `demand`, Windows only) |

## Usage

### List all services
```
service -action list
```

### Query a specific service
```
# Windows
service -action query -name Spooler

# Linux
service -action query -name sshd

# macOS
service -action query -name com.apple.sshd-keygen-wrapper
```

### Start a service
```
service -action start -name Spooler
service -action start -name nginx
```

### Stop a service
```
service -action stop -name Spooler
service -action stop -name apache2
```

### Enable a service (set to start on boot)
```
# Windows: sets start type to Automatic
service -action enable -name Spooler

# Linux: systemctl enable
service -action enable -name sshd

# macOS: launchctl enable
service -action enable -name com.apple.sshd-keygen-wrapper
```

### Disable a service
```
# Windows: sets start type to Disabled
service -action disable -name WinDefend

# Linux: systemctl disable
service -action disable -name cups

# macOS: launchctl disable
service -action disable -name com.apple.sshd-keygen-wrapper
```

### Create a new service (Windows only)
```
service -action create -name MyService -binpath "C:\path\to\binary.exe" -display "My Custom Service" -start auto
```

### Delete a service (Windows only)
```
service -action delete -name MyService
```

## Output Format

### Windows
The `list` action returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "name": "Spooler",
    "state": "Running",
    "display_name": "Print Spooler"
  }
]
```

### Linux
The `list` action returns a JSON array with systemd unit information:
```json
[
  {
    "name": "sshd",
    "load": "loaded",
    "active": "active",
    "sub": "running",
    "description": "OpenSSH server daemon",
    "enabled": "enabled"
  }
]
```

The `query` action returns detailed service properties including description, state, PID, memory usage, and the unit file contents.

### macOS
The `list` action returns a JSON array from `launchctl list`:
```json
[
  {
    "pid": "123",
    "status": "0",
    "label": "com.apple.sshd-keygen-wrapper",
    "domain": "system"
  }
]
```

The `query` action returns `launchctl print` output plus the plist file contents if found.

## Operational Notes

- **Linux:** `create` and `delete` actions are not supported (use `systemd-persist` for creating systemd services)
- **Linux:** `list` makes two systemctl calls to combine runtime state with enabled/disabled status
- **Linux:** `query` reads the unit file contents directly for inspection (no subprocess for file reading)
- Requires appropriate privileges for start/stop/enable/disable operations
- On Linux, service names can be specified with or without `.service` suffix
- **macOS:** `create` and `delete` actions are not supported (use `launch-agent` for creating LaunchAgents/Daemons)
- **macOS:** Uses `launchctl print` for detailed queries, falling back to `launchctl list <label>` if domain access is denied
- **macOS:** Searches system and user LaunchDaemon/LaunchAgent directories for plist files
- **macOS:** Start uses `launchctl kickstart` (preferred) with `launchctl load` as fallback

## MITRE ATT&CK Mapping

- **T1543.003** — Create or Modify System Service: Windows Service
- **T1543.004** — Create or Modify System Service: Launch Daemon/Agent (macOS)
- **T1562.001** — Impair Defenses: Disable or Modify Tools (enable/disable actions)
- **T1569.002** — System Services: Service Execution
