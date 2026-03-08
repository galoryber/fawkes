+++
title = "persist-enum"
chapter = false
weight = 100
hidden = false
+++

{{% notice info %}}Windows, Linux, and macOS{{% /notice %}}

## Summary

Enumerate persistence mechanisms without making any changes. Cross-platform command with platform-specific checks.

### Windows
Registry Run keys, startup folders, Winlogon hijacks, IFEO, AppInit_DLLs, scheduled tasks, non-Microsoft services.

### Linux
Cron jobs (system + user), systemd services/timers, shell profiles, init.d scripts, rc.local, XDG autostart, SSH authorized_keys, LD_PRELOAD.

### macOS
LaunchAgents/LaunchDaemons (non-Apple), cron jobs, shell profiles, login/logout hooks, SSH authorized_keys, periodic scripts.

## Categories by Platform

### Windows
| Category | What It Checks |
|----------|---------------|
| `registry` | HKLM/HKCU Run, RunOnce, RunServices, RunServicesOnce |
| `startup` | User and All Users startup folders |
| `winlogon` | Winlogon Shell, Userinit, AppInit_DLLs, TaskMan (flags non-default values) |
| `ifeo` | Image File Execution Options — Debugger entries on all subkeys |
| `appinit` | AppInit_DLLs (64-bit and WOW64) with enabled/disabled status |
| `tasks` | Non-Microsoft scheduled tasks via `schtasks /query` |
| `services` | Non-Microsoft Win32 services |

### Linux
| Category | What It Checks |
|----------|---------------|
| `cron` | /etc/crontab, /etc/cron.d/*, user crontabs, cron.hourly/daily/weekly/monthly |
| `systemd` | /etc/systemd/system/ and ~/.config/systemd/user/ (.service and .timer files) |
| `shell` | System profiles (/etc/profile, /etc/bash.bashrc), user profiles (.bashrc, .zshrc, etc.), /etc/profile.d/ |
| `startup` | /etc/rc.local, /etc/init.d/ scripts, XDG autostart (.desktop files) |
| `ssh` | ~/.ssh/authorized_keys, /root/.ssh/authorized_keys |
| `preload` | /etc/ld.so.preload, LD_PRELOAD env var, /etc/environment |

### macOS
| Category | What It Checks |
|----------|---------------|
| `launchd` | ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons (non-Apple plists) |
| `cron` | /etc/crontab, user crontabs |
| `shell` | User profiles (.zshrc, .bash_profile, etc.), system profiles (/etc/profile, /etc/zshrc) |
| `login` | Login/Logout hooks (com.apple.loginwindow), SSH authorized_keys |
| `periodic` | /etc/periodic/daily, weekly, monthly scripts |

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| category | No | Which category to enumerate (default: `all`). Platform-specific — see tables above. |

## Usage

```
# Enumerate all persistence mechanisms
persist-enum
persist-enum -category all

# Windows examples
persist-enum -category registry
persist-enum -category tasks

# Linux examples
persist-enum -category cron
persist-enum -category systemd
persist-enum -category preload

# macOS examples
persist-enum -category launchd
persist-enum -category login
```

## Notes

- Read-only — no modifications are made to the system
- **Windows**: Scheduled task enumeration uses `schtasks.exe /query`; service enumeration filters standard Windows service paths
- **Linux**: Reads /proc and filesystem only — no process spawning required
- **macOS**: LaunchAgent/Daemon enumeration filters Apple system plists (com.apple.*); login hook check uses `defaults read`
- Useful for situational awareness before or after deploying persistence

## MITRE ATT&CK Mapping

- **T1547** — Boot or Logon Autostart Execution
- **T1053** — Scheduled Task/Job
- **T1543** — Create or Modify System Process
