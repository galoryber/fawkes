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

Automatically patch a function in a loaded DLL by scanning for the nearest return (`C3`) instruction and inserting a jump to it. This effectively makes the function return immediately, which is useful for bypassing security mechanisms like AMSI or ETW.

### Arguments

#### dll_name
Name of the DLL containing the target function (e.g., `amsi`).

#### function_name
Name of the function to patch (e.g., `AmsiScanBuffer`).

#### num_bytes
Number of bytes to scan forward looking for a return instruction.

## Usage
```
autopatch <dll_name> <function_name> <num_bytes>
```

Example
```
autopatch amsi AmsiScanBuffer 300
autopatch ntdll EtwEventWrite 300
autopatch ntdll EtwEventRegister 300
```

## MITRE ATT&CK Mapping

- T1055
- T1562.001
