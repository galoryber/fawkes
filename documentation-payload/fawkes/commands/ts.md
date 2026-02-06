+++
title = "ts"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

List threads in processes. By default shows only alertable threads (Suspended/ExecutionDelay state), which are useful targets for APC injection. Use `-a` to show all threads.

### Arguments

#### -a (optional)
Show all threads, not just alertable ones.

#### -i PID (optional)
Filter threads by a specific process ID.

## Usage
```
ts [-a] [-i PID]
```

Example
```
ts
ts -a
ts -i 1234
```

## MITRE ATT&CK Mapping

- T1057
