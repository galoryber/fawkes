+++
title = "uptime"
chapter = false
weight = 208
hidden = false
+++

## Summary

Display system uptime, boot time, and load averages. Quick situational awareness check to understand how long the target has been running and when it was last rebooted.

## Arguments

No arguments required.

## Usage

```
uptime
```

## Platform Details

### Linux
- Reads `/proc/uptime` for precise uptime in seconds
- Reads `/proc/loadavg` for 1/5/15 minute load averages
- Calculates boot time from current time minus uptime

### Windows
- Uses `GetTickCount64` API for milliseconds since boot
- Calculates boot time from current time minus tick count

### macOS
- Uses `sysctl kern.boottime` for exact boot timestamp
- Calculates uptime from boot time to current time

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
