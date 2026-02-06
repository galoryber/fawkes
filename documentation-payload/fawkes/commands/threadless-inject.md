+++
title = "threadless-inject"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Inject shellcode into a remote process using threadless injection. This technique hooks a DLL function in the target process so that shellcode executes when the hooked function is naturally called. No new threads are created, making it stealthier than traditional injection methods.

Based on [CCob's ThreadlessInject](https://github.com/CCob/ThreadlessInject).

### Arguments

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Process ID
Target process ID to inject into.

#### DLL Name (optional)
DLL containing the function to hook. Default: `kernelbase.dll`.

#### Function Name (optional)
Function to hook. Default: `CreateEventW`.

## Usage

Use the Mythic UI popup to select shellcode and configure the injection target.

## Detailed Summary

The technique works by:
1. Allocating memory in the target process for the shellcode and a trampoline
2. Reading the first bytes of the target function
3. Writing a trampoline that executes the shellcode then jumps back to the original function
4. Overwriting the target function's entry point to redirect to the trampoline
5. Shellcode executes the next time the target process calls the hooked function

## MITRE ATT&CK Mapping

- T1055
