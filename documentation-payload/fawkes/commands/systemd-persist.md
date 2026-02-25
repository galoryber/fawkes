+++
title = "systemd-persist"
chapter = false
weight = 108
hidden = false
+++

## Summary

Install, remove, or list systemd service persistence. Creates a `.service` unit file (and optional `.timer` unit) in either the user directory (`~/.config/systemd/user/`) or the system directory (`/etc/systemd/system/`). Services are configured with `Restart=on-failure` for automatic recovery.

{{% notice info %}}Linux Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `install`: create service unit, `remove`: delete service unit, `list`: enumerate all units |
| name | Install/Remove | Unit name without `.service` suffix |
| exec_start | Install | Full command to execute (e.g., `/usr/bin/sleep 3600`) |
| description | No | Service description (defaults to `<name> service`) |
| system | No | `true` for system-level service (`/etc/systemd/system/`), default is user-level |
| restart_sec | No | Seconds between restart attempts (minimum 1, default 10) |
| timer | No | systemd calendar expression for periodic execution (e.g., `*-*-* *:00/5:00`) |

## Usage

```
# List all user and system services
systemd-persist -action list

# Install a user-level service
systemd-persist -action install -name myservice -exec_start "/usr/bin/sleep 3600" -description "My Service"

# Install a system-level service (requires root)
systemd-persist -action install -name myservice -exec_start "/opt/payload" -system true

# Install a service with a periodic timer
systemd-persist -action install -name mytimer -exec_start "/usr/bin/echo hello" -timer "*-*-* *:00/5:00"

# Remove a service (and its timer if present)
systemd-persist -action remove -name myservice
```

## Unit File Structure

The `install` action creates a standard systemd unit file:

```ini
[Unit]
Description=My Service
After=network.target    # system-level only

[Service]
Type=simple
ExecStart=/usr/bin/sleep 3600
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target  # user-level
# or
WantedBy=multi-user.target  # system-level
```

When a `timer` is specified, an additional `.timer` unit is created with `OnCalendar` and `Persistent=true`.

## OPSEC Considerations

- User-level services require no elevated privileges and persist across reboots (if lingering is enabled)
- System-level services require root but are more reliable for persistence
- Unit files are visible via `systemctl list-unit-files` and in the filesystem
- The command writes files but does not run `systemctl enable` — the operator must activate manually
- `remove` deletes the unit files but does not run `systemctl disable` — cleanup instructions are provided

## MITRE ATT&CK Mapping

- **T1543.002** — Create or Modify System Process: Systemd Service
