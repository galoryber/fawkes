+++
title = "read-memory"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Read bytes from a DLL function's memory address. Useful for inspecting function prologues to verify patches or understand current memory state before writing.

### Arguments

#### dll_name
Name of the DLL (e.g., `amsi`, `ntdll`).

#### function_name
Name of the function to read from.

#### start_index
Byte offset from the start of the function.

#### num_bytes
Number of bytes to read.

## Usage
```
read-memory <dll_name> <function_name> <start_index> <num_bytes>
```

Example
```
read-memory amsi AmsiScanBuffer 0 8
read-memory ntdll EtwEventWrite 0 16
```

## MITRE ATT&CK Mapping

- T1055
