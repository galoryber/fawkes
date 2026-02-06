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

{{% notice warning %}}
Argument packing is not fully functional. String arguments will crash. BOFs without arguments or with basic int/short types may work.
{{% /notice %}}

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

## Usage

Use the Mythic UI popup to select the BOF file and configure arguments.

Example
```
inline-execute    (select BOF, entry_point: go, arguments: i:80)
```

## MITRE ATT&CK Mapping

- T1620
