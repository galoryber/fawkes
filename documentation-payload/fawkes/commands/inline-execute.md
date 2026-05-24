+++
title = "inline-execute"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Execute a Beacon Object File (BOF/COFF) in memory. BOFs are small compiled C programs that run within the agent process using a minimal COFF loader.

### Arguments

#### BOF File
Select a BOF/COFF file already registered in Mythic, or upload a new one.

#### Entry Point (optional)
Entry point function name. Default: `go`.

#### BOF Arguments (optional)
Arguments in format: `<type>:<value>` separated by spaces.

Supported types:
- `z` - ASCII string
- `Z` - Wide string
- `i` - int32
- `s` - int16
- `b` - binary (base64)

#### Timeout (optional)
Execution timeout in seconds. Default: 30. Increase for long-running BOFs.

## Features

### Structured Output
BOF output is classified by Beacon API output type:
- **Standard output** (CALLBACK_OUTPUT, CALLBACK_OUTPUT_UTF8) — displayed normally
- **Error output** (CALLBACK_ERROR) — prefixed with `[ERROR]` and rendered in red in the Mythic UI

### Forge Compatibility
Supports Forge Command Augmentation for community BOFs with TypedArray arguments.

## Usage

Use the Mythic UI popup to select the BOF file and configure arguments.

Example
```
inline-execute    (select BOF, entry_point: go, arguments: i:80)
inline-execute    (select BOF, entry_point: go, arguments: z:hostname i:443, timeout: 120)
```

## MITRE ATT&CK Mapping

- T1620
