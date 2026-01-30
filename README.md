# Fawkes Mythic C2 Agent

<img src="agent_icons/fawkes.svg" width="100" />

Fawkes is my attempt at a Mythic C2 Agent. Fawkes is a golang based agent that will have cross platform agent capabilities, but currently operates on Windows. 

## Installation
To install Fawkes, you'll need Mythic installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install directory:

```
./mythic-cli install github https://github.com/galoryber/fawkes
```

## Commands Manual Quick Reference

Command | Syntax                                                                                                                | Description
------- |-----------------------------------------------------------------------------------------------------------------------| -----------
autopatch | `autopatch <dll_name> <function_name> <num_bytes>` | **(Windows only)** Automatically patch a function by jumping to nearest return (C3) instruction. Useful for AMSI/ETW bypasses.
cat | `cat <file>`                                                                                                              | Display the contents of a file.
cd | `cd <directory>`                                                                                                           | Change the current working directory.
cp | `cp <source> <destination>`                                                                                                | Copy a file from source to destination.
download | `download <path>`                                                                                                          | Download a file from the target. Supports chunked file transfer for any file size and file browser integration.
exit | `exit`                                                                                                                   | Task agent to exit.
inline-assembly | `inline-assembly`                                                                                                          | **(Windows only)** Execute a .NET assembly in memory using the CLR. Select from previously uploaded assemblies or upload a new one. Supports command-line arguments. Use `start-clr` first for AMSI patching workflow.
inline-execute | `inline-execute`                                                                                                          | **(Windows only)** Execute a Beacon Object File (BOF/COFF) in memory. Select from previously uploaded BOF files or upload a new one. **Note:** Argument packing is not fully functional - string arguments will crash. BOFs without arguments or with basic int/short types may work.
ls | `ls [path]`                                                                                                        | List files and folders in `[path]`. Defaults to current working directory.
make-token | `make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]` | **(Windows only)** Create a token from credentials and impersonate it. Default logon type 9 (NEW_CREDENTIALS) only affects NETWORK identity (like `runas /netonly`) - whoami still shows original user. Use `-logon_type 2` (INTERACTIVE) to change both local and network identity.
mkdir | `mkdir <directory>`                                                                                                        | Create a new directory (creates parent directories if needed).
mv | `mv <source> <destination>`                                                                                                | Move or rename a file from source to destination.
poolparty-injection | `poolparty-injection` | **(Windows only)** Inject shellcode using PoolParty techniques that abuse Windows Thread Pool internals. Supports Variant 1 (Worker Factory Start Routine Overwrite) and Variant 7 (TP_DIRECT Insertion). See notes below.
ps | `ps [-v] [-i PID] [filter]`                                                                                               | List running processes. Use -v for verbose output with command lines. Use -i to filter by specific PID. Optional filter to search by process name.
pwd | `pwd`                                                                                                                     | Print working directory.
read-memory | `read-memory <dll_name> <function_name> <start_index> <num_bytes>` | **(Windows only)** Read bytes from a DLL function address. Example: `read-memory amsi AmsiScanBuffer 0 8`
rev2self | `rev2self` | **(Windows only)** Revert to the original security context by dropping any active impersonation token.
rm | `rm <path>`                                                                                                                | Remove a file or directory (recursively removes directories).
run | `run <command>`                                                                                                            | Execute a shell command and return the output.
screenshot | `screenshot` | **(Windows only)** Capture a screenshot of the current desktop session. Captures all monitors and uploads as PNG.
spawn | `spawn` | **(Windows only)** Spawn a suspended process or thread for injection techniques. Process mode creates a new process with CREATE_SUSPENDED. Thread mode creates a suspended thread in an existing process. Returns PID/TID for use with `apc-injection`.
sleep | `sleep [seconds] [jitter]`                                                                                                       | Set the callback interval in seconds and jitter percentage.
start-clr | `start-clr`                                                                                                                | **(Windows only)** Initialize the CLR v4.0.30319 and load amsi.dll into memory. Run this before `inline-assembly` to implement your own AMSI bypass using `write-memory` or `autopatch`.
steal-token | `steal-token <pid>` | **(Windows only)** Steal and impersonate a security token from another process. Changes LOCAL and NETWORK identity. Requires admin privileges or SeDebugPrivilege to steal from other users' processes.
threadless-inject | `threadless-inject`                                                                                                        | **(Windows only)** Inject shellcode using threadless injection by hooking a DLL function in a remote process. Default target: kernelbase.dll!CreateEventW. More stealthy than vanilla injection as it doesn't create new threads.
upload | `upload`                                                                                                                   | Upload a file to the target with chunked file transfer. Use modal popup to select file and destination path.
vanilla-injection | `vanilla-injection`                                                                                                        | **(Windows only)** Inject shellcode into a remote process using VirtualAllocEx/WriteProcessMemory/CreateRemoteThread. Select shellcode file and target PID.
write-memory | `write-memory <dll_name> <function_name> <start_index> <hex_bytes>` | **(Windows only)** Write bytes to a DLL function address. Example: `write-memory amsi AmsiScanBuffer 0 909090`




## Supported C2 Profiles

### [HTTP Profile](https://github.com/MythicC2Profiles/http)

The HTTP profile calls back to the Mythic server over the basic, non-dynamic profile.


## Thanks
Everything I know about Mythic Agents came from Mythic Docs or stealing code and ideas from the [Merlin](https://github.com/MythicAgents/merlin) and [Freyja](https://github.com/MythicAgents/freyja) agents. 

And when that didn't work, I had Claude reference Merlin Freyja and Apollo for design choices and code references. 

In other words, I wrote nearly none of this. :) Thanks everybody else!

## Specific techniques and implementations adapted from:
- **Threadless Injection** - [CCob's ThreadlessInject](https://github.com/CCob/ThreadlessInject) (original C# implementation) and [dreamkinn's go-ThreadlessInject](https://github.com/dreamkinn/go-ThreadlessInject) (Go port)
- **sRDI (Shellcode Reflective DLL Injection)** - [Merlin's Go-based sRDI implementation](https://github.com/MythicAgents/merlin), originally based on [Nick Landers' (monoxgas) sRDI](https://github.com/monoxgas/sRDI)
- **PoolParty Injection** - [SafeBreach Labs PoolParty research](https://github.com/SafeBreach-Labs/PoolParty) (original C++ PoC)

## Command Notes

### PoolParty Injection

PoolParty injection abuses Windows Thread Pool internals to achieve code execution without calling monitored APIs like `CreateRemoteThread`. Two variants are implemented:

| Variant | Technique | Go Shellcode Compatible |
|---------|-----------|------------------------|
| 1 | Worker Factory Start Routine Overwrite | No |
| 7 | TP_DIRECT Insertion (I/O Completion Port) | Yes |

**Go-based Shellcode Compatibility:** Variant 1 executes shellcode as a thread pool worker initialization routine, which has specific constraints on stack/context setup that conflict with Go's runtime expectations (TLS setup, thread state, etc.). Variant 7's I/O completion callback context is more compatible with Go's runtime. For Go-based agent shellcode (fawkes, merlin, etc.), **use Variant 7**.

Simple shellcode (e.g., msfvenom calc.bin) works with both variants.



# References
https://openclipart.org/detail/229408/colorful-phoenix-line-art-12
https://openclipart.org/detail/228829/phoenix-line-art