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
ls | `ls [path]`                                                                                                        | List files and folders in `[path]`. Defaults to current working directory.
mkdir | `mkdir <directory>`                                                                                                        | Create a new directory (creates parent directories if needed).
mv | `mv <source> <destination>`                                                                                                | Move or rename a file from source to destination.
ps | `ps [-v] [-i PID] [filter]`                                                                                               | List running processes. Use -v for verbose output with command lines. Use -i to filter by specific PID. Optional filter to search by process name.
pwd | `pwd`                                                                                                                     | Print working directory.
read-memory | `read-memory <dll_name> <function_name> <start_index> <num_bytes>` | **(Windows only)** Read bytes from a DLL function address. Example: `read-memory amsi AmsiScanBuffer 0 8`
rm | `rm <path>`                                                                                                                | Remove a file or directory (recursively removes directories).
run | `run <command>`                                                                                                            | Execute a shell command and return the output.
sleep | `sleep [seconds] [jitter]`                                                                                                       | Set the callback interval in seconds and jitter percentage.
start-clr | `start-clr`                                                                                                                | **(Windows only)** Initialize the CLR v4.0.30319 and load amsi.dll into memory. Run this before `inline-assembly` to implement your own AMSI bypass using `write-memory` or `autopatch`.
upload | `upload`                                                                                                                   | Upload a file to the target with chunked file transfer. Use modal popup to select file and destination path.
write-memory | `write-memory <dll_name> <function_name> <start_index> <hex_bytes>` | **(Windows only)** Write bytes to a DLL function address. Example: `write-memory amsi AmsiScanBuffer 0 909090`



## Supported C2 Profiles

### [HTTP Profile](https://github.com/MythicC2Profiles/http)

The HTTP profile calls back to the Mythic server over the basic, non-dynamic profile.


## Thanks
Everything I know about Mythic Agents came from Mythic Docs or stealing code and ideas from the [Merlin](https://github.com/MythicAgents/merlin) and [Freyja](https://github.com/MythicAgents/freyja) agents. 

And when that didn't work, I had Claude reference Merlin Freyja and Apollo for design choices and code references. 

In other words, I wrote nearly none of this. :) Thanks everybody else!

# References
https://openclipart.org/detail/229408/colorful-phoenix-line-art-12
https://openclipart.org/detail/228829/phoenix-line-art