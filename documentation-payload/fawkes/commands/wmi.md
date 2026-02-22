+++
title = "wmi"
chapter = false
weight = 200
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Execute WMI queries and remote process creation via COM API (no subprocess creation). Uses SWbemLocator COM interface for queries and Win32_Process.Create method for remote execution. Supports local and remote targets.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | - | `execute`, `query`, `process-list`, or `os-info` |
| target | string | No | - | Remote host to target. If omitted, runs against the local system. |
| command | string | No | - | Command to execute. Required when action is `execute`. |
| query | string | No | - | WMI query string. Required when action is `query`. |

## Usage

### Execute a Command

Run a command on the local system:
```
wmi -action execute -command "C:\Windows\Temp\payload.exe"
```

Run a command on a remote host:
```
wmi -action execute -target 192.168.1.50 -command "C:\Windows\Temp\payload.exe"
```

### Run a Custom WMI Query

Query locally:
```
wmi -action query -query "SELECT Name,ProcessId FROM Win32_Process WHERE Name='svchost.exe'"
```

Query a remote host:
```
wmi -action query -target 192.168.1.50 -query "SELECT * FROM Win32_Service WHERE State='Running'"
```

### List Processes

List processes on the local system:
```
wmi -action process-list
```

List processes on a remote host:
```
wmi -action process-list -target 192.168.1.50
```

### Get OS Information

Get OS details for the local system:
```
wmi -action os-info
```

Get OS details for a remote host:
```
wmi -action os-info -target 192.168.1.50
```

## MITRE ATT&CK Mapping

- T1047 -- Windows Management Instrumentation
