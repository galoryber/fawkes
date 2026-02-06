+++
title = "poolparty-injection"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Inject shellcode using PoolParty techniques that abuse Windows Thread Pool internals. These techniques achieve code execution without calling commonly monitored APIs like `CreateRemoteThread`. All 8 variants from the SafeBreach Labs research are implemented.

Based on [SafeBreach Labs PoolParty research](https://github.com/SafeBreach-Labs/PoolParty).

### Arguments

#### Injection Variant
Select one of 8 PoolParty variants:
- **Variant 1** - Worker Factory Start Routine Overwrite
- **Variant 2** - TP_WORK Insertion
- **Variant 3** - TP_WAIT Insertion
- **Variant 4** - TP_IO Insertion
- **Variant 5** - TP_ALPC Insertion
- **Variant 6** - TP_JOB Insertion
- **Variant 7** - TP_DIRECT Insertion
- **Variant 8** - TP_TIMER Insertion

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Target PID
The process ID to inject shellcode into.

## Usage

Use the Mythic UI popup to select the variant, shellcode, and target PID.

## Go Shellcode Compatibility

| Variant | Go Shellcode Compatible |
|---------|------------------------|
| 1 | No - early thread context conflicts with Go runtime |
| 2-8 | Yes - callback mechanisms use fully-initialized threads |

Variant 1 executes shellcode as a thread start routine which doesn't meet Go runtime requirements (TLS, scheduler state). Variants 2-8 use callback mechanisms on fully-initialized threads, making them compatible with Go-based shellcode like Fawkes.

## MITRE ATT&CK Mapping

- T1055
