+++
title = "service"
chapter = false
weight = 46
hidden = false
+++

## Summary

Manage system services — Windows via SCM API, Linux via systemctl, macOS via launchctl. Query, start, stop, create, delete, list, enable, or disable services.

- **Windows:** Uses Win32 Service Control Manager API (OpenSCManager, CreateService, etc.). No subprocess creation — all operations run in-process via `golang.org/x/sys/windows/svc/mgr`.
- **Linux:** Uses systemctl for service management. Create writes systemd unit files to `/etc/systemd/system/` and reloads the daemon. Delete stops, disables, and removes the unit file. List and query enrich output with unit file state and service details.
- **macOS:** Uses launchctl for LaunchDaemon/LaunchAgent management. Create writes launchd plist files (LaunchDaemons as root, LaunchAgents as user) and loads them. Delete unloads and removes the plist file. Query shows `launchctl print` output and plist file contents. List parses `launchctl list` output.

{{% notice info %}}Windows, Linux, and macOS{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Action to perform: `query`, `start`, `stop`, `create`, `delete`, `list`, `enable`, `disable` |
| name | Conditional | Service name (required for all actions except `list`) |
| binpath | Conditional | Path to service binary (required for `create`) |
| display | No | Display name / description for the service (for `create`) |
| start | No | Start type: `demand` (manual), `auto` (automatic), `disabled` (default: `demand`) |

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

### Create a new service
```
# Windows — creates via SCM API
service -action create -name MyService -binpath "C:\path\to\binary.exe" -display "My Custom Service" -start auto

# Linux — writes systemd unit file to /etc/systemd/system/ (requires root)
service -action create -name my-agent -binpath /opt/agent/payload -display "System Update Agent" -start auto

# macOS — writes plist to /Library/LaunchDaemons/ (root) or ~/Library/LaunchAgents/ (user)
service -action create -name com.corp.agent -binpath /opt/agent/payload -start auto
```

### Delete a service
```
# Windows — removes via SCM API
service -action delete -name MyService

# Linux — stops, disables, removes unit file, reloads systemd (requires root)
service -action delete -name my-agent

# macOS — unloads and removes plist file
service -action delete -name com.corp.agent
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

- **Linux:** `create` writes a systemd unit file with `[Unit]`, `[Service]`, and `[Install]` sections, then runs `systemctl daemon-reload`. Requires root access to write to `/etc/systemd/system/`.
- **Linux:** `delete` stops the service, disables it, removes the unit file, and reloads the daemon.
- **Linux:** `list` makes two systemctl calls to combine runtime state with enabled/disabled status
- **Linux:** `query` reads the unit file contents directly for inspection (no subprocess for file reading)
- On Linux, service names can be specified with or without `.service` suffix
- **macOS:** `create` writes a launchd plist. As root, writes to `/Library/LaunchDaemons/` (system-wide). As regular user, writes to `~/Library/LaunchAgents/` (user-level). Automatically loads the plist after creation.
- **macOS:** `delete` unloads the service via `launchctl unload` and removes the plist file.
- **macOS:** Uses `launchctl print` for detailed queries, falling back to `launchctl list <label>` if domain access is denied
- **macOS:** Searches system and user LaunchDaemon/LaunchAgent directories for plist files
- **macOS:** Start uses `launchctl kickstart` (preferred) with `launchctl load` as fallback
- Requires appropriate privileges for start/stop/enable/disable/create/delete operations

## MITRE ATT&CK Mapping

- **T1543.002** — Create or Modify System Process: Systemd Service (Linux create/delete)
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1543.004** — Create or Modify System Process: Launch Daemon/Agent (macOS create/delete)
- **T1562.001** — Impair Defenses: Disable or Modify Tools (enable/disable actions)
- **T1569.002** — System Services: Service Execution
