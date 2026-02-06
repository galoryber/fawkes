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

Initialize the .NET CLR runtime (v4.0.30319) and load `amsi.dll` into the agent process. Run this before `inline-assembly` if you want to patch AMSI before loading .NET assemblies.

### Arguments

No arguments.

## Usage
```
start-clr
```

Example workflow
```
start-clr
autopatch amsi AmsiScanBuffer 300
inline-assembly
```

## MITRE ATT&CK Mapping

- T1055.001
- T1620
