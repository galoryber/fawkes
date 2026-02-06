+++
title = "apc-injection"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Perform QueueUserAPC injection into an alertable thread. This queues an asynchronous procedure call to a thread that is in an alertable wait state (Suspended or DelayExecution).

Use the `ts` command first to find alertable threads in the target process.

### Arguments

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Target PID
The process ID containing the target thread.

#### Target Thread ID
The thread ID to queue the APC to. Use the `ts` command to identify alertable threads (Suspended/DelayExecution state).

## Usage

1. Run `ts -i <PID>` to find alertable threads in the target process
2. Use the Mythic UI popup to select shellcode and enter the PID and TID

Example workflow
```
ts -i 5432
apc-injection
```

## MITRE ATT&CK Mapping

- T1055.004
