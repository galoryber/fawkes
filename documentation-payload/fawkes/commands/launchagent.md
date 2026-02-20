+++
title = "launchagent"
chapter = false
weight = 35
hidden = false
+++

{{% notice info %}}macOS Only{{% /notice %}}

## Summary

Install, remove, or list macOS LaunchAgent and LaunchDaemon persistence mechanisms. Creates properly formatted plist files with `RunAtLoad` and `KeepAlive` for automatic execution on login (LaunchAgent) or boot (LaunchDaemon).

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | install | `install`, `remove`, or `list` |
| label | string | No | - | Reverse-DNS label for the plist (e.g., `com.apple.security.updater`). Becomes the filename. |
| path | string | No | agent binary | Path to the executable to persist. Defaults to the agent binary. |
| args | string | No | - | Optional arguments for the executable |
| daemon | boolean | No | false | Use LaunchDaemon (system-wide, `/Library/LaunchDaemons/`, requires root) instead of LaunchAgent (user-level) |
| interval | number | No | 0 | Optional: restart interval in seconds (e.g., 3600 = every hour) |
| run_at | string | No | - | Optional: calendar schedule. Format: `HH:MM` (daily) or `weekday HH:MM` (0=Sun, 1=Mon, etc.) |

## Usage

### List Persistence Entries

Enumerate all LaunchAgent and LaunchDaemon plists:
```
launchagent -action list
```

### Install LaunchAgent (User-Level)

Install persistence as a user-level LaunchAgent (runs on login, no root needed):
```
launchagent -action install -label com.apple.security.updater -path /tmp/agent
```

Install with default path (current agent binary):
```
launchagent -action install -label com.apple.security.updater
```

Install with a restart interval (every hour):
```
launchagent -action install -label com.apple.sync.helper -path /tmp/agent -interval 3600
```

Install with calendar schedule (daily at 9am):
```
launchagent -action install -label com.apple.sync.helper -path /tmp/agent -run_at "09:00"
```

### Install LaunchDaemon (System-Level, Root Required)

Install as a system-wide LaunchDaemon (runs on boot, requires root):
```
launchagent -action install -label com.apple.security.updater -path /tmp/agent -daemon true
```

### Remove Persistence

Remove a LaunchAgent plist:
```
launchagent -action remove -label com.apple.security.updater
```

Remove a LaunchDaemon:
```
launchagent -action remove -label com.apple.security.updater -daemon true
```

### Example Output (list)

```
=== macOS Persistence ===

--- User LaunchAgents: /Users/gary/Library/LaunchAgents ---
  com.apple.security.updater (412 bytes)

--- System LaunchAgents: /Library/LaunchAgents ---
  com.apple.AirPlayUIAgent (238 bytes)
  com.apple.SafariCloudHistoryPushAgent (516 bytes)

--- LaunchDaemons: /Library/LaunchDaemons ---
  com.apple.ManagedClient (1024 bytes)
```

### Example Output (install)

```
Installed LaunchAgent persistence:
  Label:   com.apple.security.updater
  Path:    /tmp/agent
  Plist:   /Users/gary/Library/LaunchAgents/com.apple.security.updater.plist
  Trigger: RunAtLoad (on login)
```

## Notes

- **LaunchAgent** (default): User-level persistence. Runs when the user logs in. Plist stored in `~/Library/LaunchAgents/`. No root required.
- **LaunchDaemon** (`-daemon true`): System-level persistence. Runs at boot before login. Plist stored in `/Library/LaunchDaemons/`. Requires root.
- All plists include `RunAtLoad` (execute immediately when loaded) and `KeepAlive` (restart if the process dies).
- Use labels that blend with legitimate Apple services (e.g., `com.apple.security.updater`).
- To unload a currently running agent, use `run launchctl remove <label>` before removing the plist.

## MITRE ATT&CK Mapping

- T1543.004 — Create or Modify System Process: Launch Agent
