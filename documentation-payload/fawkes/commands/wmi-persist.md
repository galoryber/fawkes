+++
title = "wmi-persist"
chapter = false
weight = 107
hidden = false
+++

## Summary

Install, remove, or list WMI Event Subscription persistence. Creates a persistent event filter + command-line consumer + binding that survives reboots. This is a fileless persistence technique that lives entirely in the WMI repository (`root\subscription` namespace).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `install`: create subscription, `remove`: delete subscription, `list`: enumerate all subscriptions |
| name | Install/Remove | Identifier prefix for filter, consumer, and binding |
| command | Install | Full command line to execute when the event fires |
| trigger | Install | Event trigger type: `logon`, `startup`, `interval`, `process` |
| interval_sec | No | Interval in seconds for periodic trigger (minimum 10, default 300) |
| process_name | Process trigger | Process name to watch for (e.g., `notepad.exe`) |
| target | No | Remote host for WMI connection (empty = localhost) |

## Trigger Types

| Trigger | WQL Event | Description |
|---------|-----------|-------------|
| `logon` | `__InstanceCreationEvent` on `Win32_LogonSession` | Fires when any user logs in |
| `startup` | `__InstanceModificationEvent` on `Win32_PerfFormattedData_PerfOS_System` | Fires after system boot (uptime >= 120s) |
| `interval` | `__TimerEvent` with `__IntervalTimerInstruction` | Fires periodically at configured interval |
| `process` | `__InstanceCreationEvent` on `Win32_Process` | Fires when a specific process starts |

## Usage

```
# Install persistence with logon trigger
wmi-persist -action install -name backdoor -trigger logon -command "C:\payload.exe"

# Install persistence with process trigger
wmi-persist -action install -name monitor -trigger process -process_name notepad.exe -command "C:\payload.exe"

# Install periodic execution (every 5 minutes)
wmi-persist -action install -name timer -trigger interval -interval_sec 300 -command "C:\payload.exe"

# List all WMI event subscriptions
wmi-persist -action list

# Remove a subscription
wmi-persist -action remove -name backdoor
```

## WMI Objects Created

The `install` action creates three WMI objects in `root\subscription`:

1. **`__EventFilter`** (`<name>_Filter`) — defines the trigger condition via WQL query
2. **`CommandLineEventConsumer`** (`<name>_Consumer`) — defines the command to execute
3. **`__FilterToConsumerBinding`** — links the filter to the consumer

For `interval` triggers, an additional `__IntervalTimerInstruction` object is created to generate periodic timer events.

## OPSEC Considerations

- WMI subscriptions persist in the WMI repository (not the filesystem) — no files on disk
- Subscription metadata is visible via `wmic`, `Get-WMIObject`, or this command's `list` action
- Event ID 5861 is logged in `Microsoft-Windows-WMI-Activity/Operational` when subscriptions fire
- `CommandLineEventConsumer` executes as SYSTEM regardless of trigger context
- Always clean up test subscriptions with `remove` action

## MITRE ATT&CK Mapping

- **T1546.003** — Event Triggered Execution: Windows Management Instrumentation Event Subscription
