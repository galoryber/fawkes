+++
title = "service"
chapter = false
weight = 46
hidden = false
+++

## Summary

Manage Windows services — query, start, stop, create, or delete services using the Win32 Service Control Manager API (OpenSCManager, CreateService, etc.). No subprocess creation — all operations run in-process via `golang.org/x/sys/windows/svc/mgr`.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Action to perform: `query`, `start`, `stop`, `create`, `delete`, or `list` |
| name | Conditional | Service name (required for all actions except `list`) |
| binpath | Conditional | Path to service binary (required for `create`) |
| display | No | Display name for the service (for `create`) |
| start | No | Start type: `demand` (manual), `auto` (automatic), `disabled` (default: `demand`) |

## Usage

### List all services
```
service -action list
```

### Query a specific service
```
service -action query -name Spooler
```

### Start a service
```
service -action start -name Spooler
```

### Stop a service
```
service -action stop -name Spooler
```

### Create a new service
```
service -action create -name MyService -binpath "C:\path\to\binary.exe" -display "My Custom Service" -start auto
```

### Delete a service
```
service -action delete -name MyService
```

## Output Format

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

The browser script highlights running services in blue. Other actions (query, start, stop, create, delete) return plain text status messages.

## MITRE ATT&CK Mapping

- **T1543.003** — Create or Modify System Service: Windows Service
- **T1569.002** — System Services: Service Execution
