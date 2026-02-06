+++
title = "inline-assembly"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Execute a .NET assembly in memory using the Common Language Runtime (CLR). The assembly runs within the agent's process. Supports command-line arguments.

Run `start-clr` first if you want to implement AMSI bypasses before loading assemblies.

### Arguments

#### .NET Assembly
Select a .NET assembly file already registered in Mythic, or upload a new one.

#### Assembly Arguments (optional)
Command-line arguments to pass to the assembly, space-separated.

## Usage

Use the Mythic UI popup to select the assembly and provide arguments.

Example workflow
```
start-clr
autopatch amsi AmsiScanBuffer 300
inline-assembly    (select Seatbelt.exe, args: --groups=all)
```

## MITRE ATT&CK Mapping

- T1055.001
- T1620
