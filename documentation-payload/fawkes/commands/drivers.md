+++
title = "drivers"
chapter = false
weight = 121
hidden = false
+++

## Summary

Enumerate loaded kernel drivers and modules. Useful for identifying security products at the kernel level (EDR drivers, AV kernel components), understanding system configuration, and finding potential targets for driver-based attacks.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| filter | No | — | Case-insensitive name filter (substring match against name and path) |

## Usage

### List all loaded drivers
```
drivers
```

### Filter by name
```
drivers -filter ntfs
```

### Search for security drivers
```
drivers -filter crowd
```

## Platform Details

### Windows
Uses `EnumDeviceDrivers` API from `psapi.dll` to enumerate all loaded kernel drivers. Returns driver name (base name) and full path (e.g., `\SystemRoot\system32\ntoskrnl.exe`). Typical systems have 150-200+ loaded drivers.

### Linux
Parses `/proc/modules` to enumerate loaded kernel modules. Returns module name, size, status (live/loading/unloading), and dependent modules. Typical systems have 30-100+ loaded modules.

### macOS
Enumerates kernel extensions (`.kext` files) from `/Library/Extensions` and `/System/Library/Extensions`, plus system extensions from `/Library/SystemExtensions`. Reads version info from `Info.plist` when available.

## OPSEC Considerations

- Read-only enumeration — no disk writes or system modifications
- Uses standard APIs (psapi.dll on Windows, /proc on Linux) — minimal footprint
- Complements `av-detect` (which scans processes) with kernel-level visibility

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
