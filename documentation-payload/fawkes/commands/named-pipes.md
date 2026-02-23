+++
title = "named-pipes"
chapter = false
weight = 109
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

List named pipes on the system using FindFirstFile/FindNextFile on `\\.\pipe\*`. Named pipes are a common Windows IPC mechanism used by services, applications, and security tools.

This is useful for:
- **IPC discovery**: Identify inter-process communication channels
- **Privilege escalation recon**: Find pipes that may be exploitable (e.g., PrintSpoofer, JuicyPotato pipe targets)
- **Lateral movement planning**: Discover service pipes that accept remote connections
- **Security product detection**: Many AV/EDR solutions create distinctive named pipes

## Arguments

### filter
Optional case-insensitive substring filter. Only show pipes matching this pattern.

## Usage

List all named pipes:
```
named-pipes
```

Filter for specific pipes:
```
named-pipes -filter sql
named-pipes -filter spool
named-pipes -filter mojo
```

## Example Output

```
Named pipes: 67

  \\.\pipe\BackingAppCommandPipe
  \\.\pipe\InitShutdown
  \\.\pipe\MSSQL$SQLEXPRESS\sql\query
  \\.\pipe\SQLLocal\SQLEXPRESS
  \\.\pipe\lsass
  \\.\pipe\ntsvcs
  \\.\pipe\openssh-ssh-agent
  \\.\pipe\srvsvc
  \\.\pipe\trkwks
  \\.\pipe\wkssvc
  ...
```

## MITRE ATT&CK Mapping

- T1083 — File and Directory Discovery (pipe enumeration)
