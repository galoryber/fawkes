+++
title = "container-detect"
chapter = false
weight = 211
hidden = false
+++

## Summary

Detect container runtime and environment type. Identifies Docker, Kubernetes, LXC, Podman, WSL, and containerd environments by checking filesystem indicators, cgroup entries, environment variables, and capabilities. Also checks for container escape vectors like mounted Docker sockets and Kubernetes service accounts.

Useful for situational awareness when the execution environment is unknown — understanding if you're in a container affects which techniques are available and which escape paths exist.

## Arguments

No arguments required.

## Usage

```
container-detect
```

## Platform Details

### Linux
- Checks `/.dockerenv` (Docker indicator)
- Checks `/run/.containerenv` (Podman indicator)
- Parses `/proc/1/cgroup` for docker/kubepods/lxc/containerd strings
- Checks `/proc/1/environ` for `KUBERNETES_*` and `container=` env vars
- Checks `/var/run/secrets/kubernetes.io` for K8s service accounts
- Checks for Docker socket mounts (`/var/run/docker.sock`) — escape vector
- Checks `/proc/1/sched` for PID 1 identity (systemd = host, other = container)
- Checks `/proc/version` for WSL kernel indicators
- Reports effective capabilities (`CapEff`) — reduced caps suggest containerization

### Windows
- Checks for WSL availability (`wsl.exe`)
- Checks for Docker Desktop installation
- Checks for Windows container indicators (Nano Server/Server Core)

### macOS
- Checks for Docker Desktop and OrbStack installations
- macOS does not typically run inside containers

## OPSEC Considerations

- All checks are passive filesystem reads — no network traffic or process creation
- Reading `/proc` entries is normal system behavior and unlikely to trigger alerts

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
- **T1497.001** — Virtualization/Sandbox Evasion: System Checks
