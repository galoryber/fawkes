+++
title = "vanilla-injection"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Inject shellcode into a remote process using the classic VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread technique. This is the most straightforward injection method but also the most commonly monitored.

### Arguments

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Target PID
The process ID to inject shellcode into.

## Usage

Use the Mythic UI popup to select shellcode and enter the target PID.

## MITRE ATT&CK Mapping

- T1055.001
- T1055.002
