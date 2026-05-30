+++
title = "wmi-persist"
chapter = false
weight = 107
hidden = false
+++

## Summary

Install, remove, or list WMI Event Subscription persistence. Creates a persistent event filter + consumer + binding that survives reboots. This is a fileless persistence technique that lives entirely in the WMI repository (`root\subscription` namespace).

Supports two consumer types:
- **CommandLineEventConsumer** — executes a command line when the event fires
- **ActiveScriptEventConsumer** — runs VBScript or JScript in-memory (fully fileless)

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `install`: create subscription, `remove`: delete subscription, `list`: enumerate all subscriptions |
| name | Install/Remove | Identifier prefix for filter, consumer, and binding |
| command | Install | Command line (for command consumer) or script body (for script consumer) |
| trigger | Install | Event trigger type: `logon`, `startup`, `interval`, `process` |
| consumer_type | No | `command` (default): execute command line, `script`: run VBScript/JScript |
| script_engine | No | Scripting engine for script consumer: `VBScript` (default) or `JScript` |
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
# Install persistence with logon trigger (command consumer)
wmi-persist -action install -name backdoor -trigger logon -command "C:\payload.exe"

# Install persistence with process trigger
wmi-persist -action install -name monitor -trigger process -process_name notepad.exe -command "C:\payload.exe"

# Install periodic execution (every 5 minutes)
wmi-persist -action install -name timer -trigger interval -interval_sec 300 -command "C:\payload.exe"

# Install fileless script persistence (VBScript)
wmi-persist -action install -name scriptback -trigger logon -consumer_type script -command "Set ws = CreateObject(\"Wscript.Shell\")\nws.Run \"C:\payload.exe\", 0, False"

# Install JScript persistence
wmi-persist -action install -name jsback -trigger startup -consumer_type script -script_engine JScript -command "var ws = new ActiveXObject('WScript.Shell'); ws.Run('C:\\\\payload.exe', 0, false);"

# List all WMI event subscriptions
wmi-persist -action list

# Remove a subscription (auto-detects consumer type)
wmi-persist -action remove -name backdoor
```

## Consumer Types

### CommandLineEventConsumer (default)

Executes a command line via `cmd.exe` when the event fires. The command runs as SYSTEM. This is the standard WMI persistence consumer — reliable across all Windows versions.

### ActiveScriptEventConsumer

Runs a VBScript or JScript in-memory via the WMI scripting host (`scrcons.exe`). The script executes without writing any files to disk, making it harder to detect via file-based scanning.

{{% notice warning %}}ActiveScriptEventConsumer may be disabled on modern Windows 10/11 systems. It requires `scrcons.exe` (WMI Standard Event Consumer provider) which some hardened configurations remove. Test with `list` action after install to verify the subscription was created.{{% /notice %}}

## WMI Objects Created

The `install` action creates three WMI objects in `root\subscription`:

1. **`__EventFilter`** (`<name>_Filter`) — defines the trigger condition via WQL query
2. **Consumer** (`<name>_Consumer`) — either `CommandLineEventConsumer` or `ActiveScriptEventConsumer`
3. **`__FilterToConsumerBinding`** — links the filter to the consumer

For `interval` triggers, an additional `__IntervalTimerInstruction` object is created to generate periodic timer events.

## OPSEC Considerations

- WMI subscriptions persist in the WMI repository (not the filesystem) — no files on disk
- Subscription metadata is visible via `wmic`, `Get-WMIObject`, or this command's `list` action
- Sysmon Event IDs **19** (EventFilter), **20** (EventConsumer), **21** (FilterToConsumerBinding) log subscription creation
- Event ID 5861 in `Microsoft-Windows-WMI-Activity/Operational` logs when subscriptions fire
- `CommandLineEventConsumer` executes as SYSTEM regardless of trigger context
- `ActiveScriptEventConsumer` runs via `scrcons.exe` — detectable by process creation monitoring
- Always clean up test subscriptions with `remove` action

## MITRE ATT&CK Mapping

- **T1546.003** — Event Triggered Execution: Windows Management Instrumentation Event Subscription
