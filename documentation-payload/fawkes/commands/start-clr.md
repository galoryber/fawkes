+++
title = "start-clr"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Initialize the .NET CLR runtime (v4.0.30319) and load `amsi.dll` into the agent process. Optionally apply AMSI and ETW patches to bypass security scanning before loading .NET assemblies via `inline-assembly`.

### Arguments

| Parameter | Type | Description |
|-----------|------|-------------|
| amsi_patch | ChooseOne | AMSI bypass method: **None**, **Ret Patch**, **Autopatch**, or **Hardware Breakpoint** |
| etw_patch | ChooseOne | ETW bypass method: **None**, **Ret Patch**, **Autopatch**, or **Hardware Breakpoint** |

### Patch Methods

| Method | Description | Reliability |
|--------|-------------|-------------|
| None | No patching — AMSI/ETW remain active | N/A |
| Ret Patch | Writes `0xC3` (ret) at function entry point via VirtualProtect. Simple single-byte patch. | High |
| Autopatch | Searches for nearest `C3` instruction and writes a JMP to it at function prologue. | High |
| Hardware Breakpoint | Uses debug registers + native VEH handler to intercept calls. No memory writes to target function. | Experimental (AMSI intermittent) |

### ETW Functions Patched

When ETW patching is enabled (Autopatch or Ret Patch), two functions are patched:
- **EtwEventWrite** — Prevents ETW events from being written (blocks telemetry)
- **EtwEventRegister** — Prevents new ETW providers from being registered

## Usage

Recommended workflow with Ret Patch (simplest):
```
start-clr   (select Ret Patch for AMSI and ETW)
inline-assembly   (load .NET assemblies)
```

With Autopatch:
```
start-clr   (select Autopatch for AMSI and ETW)
inline-assembly
```

Without patching (benign assemblies only):
```
start-clr
inline-assembly
```

## MITRE ATT&CK Mapping

- T1055.001 — Process Injection: Dynamic-link Library Injection
- T1620 — Reflective Code Loading
- T1562.001 — Impair Defenses: Disable or Modify Tools
