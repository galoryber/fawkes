+++
title = "etw"
chapter = false
weight = 157
hidden = false
+++

## Summary

Enumerate ETW (Event Tracing for Windows) trace sessions and security-relevant providers. This command helps operators assess what telemetry is active on the target before performing sensitive operations, enabling informed decisions about evasion techniques.

Identifies security-critical ETW providers including Sysmon, Defender, PowerShell, .NET, WinRM, kernel process/file/network/registry providers, and AMSI.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | sessions | Action: `sessions` or `providers` |

### Actions

- **sessions** — List all active ETW trace sessions with security relevance classification (Defender, Sysmon, EDR, Security, Audit, Kernel, Diagnostics)
- **providers** — Enumerate all registered ETW providers, highlighting 19 known security-relevant providers (AMSI, PowerShell, Sysmon, kernel events, etc.)

## Usage

```
# List active ETW trace sessions
etw -action sessions

# Enumerate security-relevant ETW providers
etw -action providers
```

## Operational Notes

- Use this command before performing sensitive operations to understand what telemetry is being collected
- Security-relevant sessions are flagged with `!!` (critical) or `!` (notable) markers
- Common indicators to watch for:
  - **Sysmon** — advanced process/network/registry monitoring
  - **Defender/Antimalware** — AV event collection
  - **Kernel-Process** — process creation/termination events
  - **AMSI** — script content inspection
  - **PowerShell** — PowerShell script block logging
- Consider using `autopatch` for AMSI/ETW patching after identifying active providers
- Consider using `auditpol` to disable audit policies for detected telemetry sources

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
