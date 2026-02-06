+++
title = "spawn"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Spawn a suspended process or create a suspended thread in an existing process. Useful for preparing targets for injection techniques like `apc-injection`.

### Arguments

**Process mode:**
#### Executable Path
Path to the executable to spawn suspended. Default: `C:\Windows\System32\notepad.exe`.

**Thread mode:**
#### Target PID
Process ID to create a suspended thread in.

## Usage

Use the Mythic UI popup to select Process or Thread mode and configure the target.

Example workflow
```
spawn           (creates suspended notepad.exe)
ts -i <PID>     (find the suspended thread)
apc-injection   (inject into the alertable thread)
```

## MITRE ATT&CK Mapping

- T1055
