+++
title = "named-pipes"
chapter = false
weight = 109
hidden = false
+++

{{% notice info %}}
Windows, Linux, and macOS
{{% /notice %}}

## Summary

Enumerate IPC endpoints on the system. Cross-platform command with platform-specific output.

### Windows
Lists named pipes using FindFirstFile/FindNextFile on `\\.\pipe\*`.

### Linux
Reads `/proc/net/unix` for Unix domain sockets and scans `/tmp`, `/var/run`, `/run` for FIFO named pipes.

### macOS
Scans `/var/run`, `/tmp`, `/private/var/run`, `/private/tmp` for Unix domain sockets and FIFO named pipes.

This is useful for:
- **IPC discovery**: Identify inter-process communication channels
- **Privilege escalation recon**: Find pipes that may be exploitable (e.g., PrintSpoofer, Docker socket)
- **Lateral movement planning**: Discover service sockets (SSH agent, database sockets)
- **Security product detection**: Many AV/EDR solutions create distinctive named pipes or sockets

## Arguments

### filter
Optional case-insensitive substring filter. Only show entries matching this pattern.

## Usage

List all IPC endpoints:
```
named-pipes
```

Filter for specific entries:
```
named-pipes -filter docker
named-pipes -filter mysql
named-pipes -filter spool
```

## Example Output

### Windows
```
Named pipes: 67

  \\.\pipe\lsass
  \\.\pipe\ntsvcs
  \\.\pipe\openssh-ssh-agent
  \\.\pipe\srvsvc
  ...
```

### Linux
```
Unix domain sockets: 42

  /run/dbus/system_bus_socket
  /run/systemd/journal/dev-log
  /var/run/docker.sock
  /tmp/ssh-XXXX/agent.1234
  ...

Named pipes (FIFOs): 2

  /tmp/my_fifo
  /run/initctl
```

### macOS
```
Unix domain sockets: 15

  /var/run/mDNSResponder
  /private/tmp/com.apple.launchd.XXXX/Listeners
  /var/run/syslog
  ...
```

## MITRE ATT&CK Mapping

- T1083 — File and Directory Discovery (pipe/socket enumeration)
