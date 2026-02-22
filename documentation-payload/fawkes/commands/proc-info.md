+++
title = "proc-info"
chapter = false
weight = 101
hidden = false
+++

## Summary

Deep process inspection via the Linux `/proc` filesystem. Provides detailed process information, network connections with PID resolution, mount information, and loaded kernel modules.

{{% notice info %}}Linux Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | info | Action to perform: `info`, `connections`, `mounts`, `modules` |
| pid | No | self | Target process ID (only used with `info` action). Defaults to the agent's own PID. |

### Actions

- **info** — Detailed process inspection: command line, executable path, status (UID/GID/capabilities/threads/memory), environment variables, cgroups, namespaces, open file descriptors, loaded libraries
- **connections** — Parse `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` with hex-to-human-readable address conversion and PID resolution via socket inode mapping
- **mounts** — Display filesystem mounts from `/proc/self/mounts`
- **modules** — List loaded kernel modules from `/proc/modules` with size and dependency info

## Usage

```
proc-info -action info
proc-info -action info -pid 1
proc-info -action connections
proc-info -action mounts
proc-info -action modules
```

### Example Output (info)

```
=== Process Info: PID 12345 ===

Command line: /tmp/fawkes_linux_test
Process name: fawkes_linux_te

Status:
  Name: fawkes_linux_te
  State: S (sleeping)
  PPid: 1
  Uid: 1000 1000 1000 1000
  Gid: 1000 1000 1000 1000
  CapEff: 0000000000000000
  Threads: 8
  VmRSS: 15324 kB

Executable: /tmp/fawkes_linux_test
Working dir: /tmp
Root dir: /

Environment (25 vars):
  HOME=/home/setup
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  ...

Cgroups:
  0::/user.slice/user-1000.slice/session-1.scope

Namespaces:
  cgroup -> cgroup:[4026531835]
  mnt -> mnt:[4026531841]
  net -> net:[4026531840]
  pid -> pid:[4026531836]
  ...
```

### Example Output (connections)

```
=== Network Connections ===

TCP connections:
  192.168.100.169:45678 -> 192.168.100.184:80  ESTABLISHED  PID:12345(fawkes_linux_te)
  0.0.0.0:22 -> 0.0.0.0:0  LISTEN  PID:890(sshd)
```

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1057 | Process Discovery |
| T1082 | System Information Discovery |
| T1049 | System Network Connections Discovery |
