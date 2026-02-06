+++
title = "steal-token"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Steal and impersonate a security token from another process. Changes both local and network identity. Requires administrator privileges or SeDebugPrivilege to steal tokens from other users' processes.

### Arguments

#### pid
Process ID to steal the token from (e.g., a process running as a different user).

## Usage
```
steal-token <PID>
```

Example
```
steal-token 672
```

## MITRE ATT&CK Mapping

- T1134.001
