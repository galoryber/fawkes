# Fawkes Mythic C2 Agent

<img src="agent_icons/fawkes.svg" width="100" />

Fawkes is an entirely vibe-coded Mythic C2 agent. It started as an "I wonder" and has turned into a goal. My goal is to not write a single line of code for this agent, instead, exclusively producing it at a prompt.

I originally attempted to write the agent myself, but after cloning the example container, reading through mythic docs, watching the dev series youtube videos, and copying code from other agents like Merlin or Freyja, I decided I just didn't have time to develop my own agent. A prompt though, that I have time for.

Fawkes is a golang based agent with cross-platform capabilities. It supports **Windows** (EXE, DLL, and shellcode payloads), **Linux** (ELF binaries and shared libraries), and **macOS** (Mach-O binaries for Intel and Apple Silicon). 26 commands are cross-platform, with 28 additional Windows-only commands, 1 Windows+macOS command (screenshot), 2 Unix-only commands, and 2 macOS-only commands for a total of 59.

## Installation
To install Fawkes, you'll need Mythic installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install directory:

```
./mythic-cli install github https://github.com/galoryber/fawkes
```

## Commands Quick Reference

Command | Syntax | Description
------- | ------ | -----------
apc-injection | `apc-injection` | **(Windows only)** Perform QueueUserAPC injection into an alertable thread. Use `ts` to find alertable threads (T1055.004).
arp | `arp` | Display ARP table — shows IP-to-MAC address mappings for nearby hosts. Cross-platform.
av-detect | `av-detect` | Detect installed AV/EDR/security products by scanning running processes against a 130+ signature database. Reports product, vendor, type, and PID. Cross-platform.
autopatch | `autopatch <dll_name> <function_name> <num_bytes>` | **(Windows only)** Automatically patch a function by jumping to nearest return (C3) instruction. Useful for AMSI/ETW bypasses.
cat | `cat <file>` | Display the contents of a file.
cd | `cd <directory>` | Change the current working directory.
clipboard | `clipboard -action read` / `clipboard -action write -data "text"` | **(Windows only)** Read or write the Windows clipboard contents (text only).
cp | `cp <source> <destination>` | Copy a file from source to destination.
crontab | `crontab -action <list\|add\|remove> [-entry <cron_line>] [-program <path>] [-schedule <schedule>]` | **(Linux/macOS only)** List, add, or remove cron jobs for persistence. Supports raw cron entries or program+schedule syntax.
download | `download <path>` | Download a file from the target. Supports chunked file transfer for any file size and file browser integration.
drives | `drives` | **(Windows only)** List available drives/volumes with type (Fixed/Removable/Network/CD-ROM), label, and free/total space.
env | `env [filter]` | List environment variables. Optionally filter by name (case-insensitive).
exit | `exit` | Task agent to exit.
find | `find -pattern <glob> [-path <dir>] [-max_depth <n>]` | Search for files by name pattern. Cross-platform recursive file search with depth limit.
ifconfig | `ifconfig` | List network interfaces with addresses, MAC, MTU, and flags. Cross-platform (Windows/Linux/macOS).
inline-assembly | `inline-assembly` | **(Windows only)** Execute a .NET assembly in memory using the CLR. Supports command-line arguments. Use `start-clr` first for AMSI patching workflow.
inline-execute | `inline-execute` | **(Windows only)** Execute a Beacon Object File (BOF/COFF) in memory. Supports all argument types: strings (z), wide strings (Z), integers (i), shorts (s), and binary (b).
keychain | `keychain -action <list\|dump\|find-password\|find-internet\|find-cert> [-service <name>] [-server <host>]` | **(macOS only)** Access macOS Keychain — list keychains, dump metadata, find generic/internet passwords, enumerate certificates.
keylog | `keylog -action <start\|stop\|dump>` | **(Windows only)** Low-level keyboard logger with window context. Start/stop/dump captured keystrokes.
kill | `kill -pid <PID>` | Terminate a process by PID. Cross-platform (Windows/Linux/macOS).
launchagent | `launchagent -action <install\|remove\|list> -label <com.example.name> [-path <exe>] [-daemon true]` | **(macOS only)** Install, remove, or list LaunchAgent/LaunchDaemon persistence. Creates plist with RunAtLoad+KeepAlive.
ls | `ls [path]` | List files and folders in `[path]`. Defaults to current working directory.
make-token | `make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]` | **(Windows only)** Create a token from credentials and impersonate it.
mkdir | `mkdir <directory>` | Create a new directory (creates parent directories if needed).
mv | `mv <source> <destination>` | Move or rename a file from source to destination.
net-enum | `net-enum -action <users\|localgroups\|groupmembers\|domainusers\|domaingroups\|domaininfo> [-target <group>]` | **(Windows only)** Enumerate local/domain users, groups, and domain information.
net-shares | `net-shares -action <local\|remote\|mapped> [-target <host>]` | **(Windows only)** Enumerate network shares and mapped drives.
net-stat | `net-stat` | List active network connections and listening ports with protocol, state, and PID. Cross-platform.
opus-injection | `opus-injection` | **(Windows only)** Callback-based process injection. Variant 1: Ctrl-C Handler Chain. Variant 4: PEB KernelCallbackTable. [Details](research/injection-techniques.md#opus-injection)
persist | `persist -method <registry\|startup-folder\|list> -action <install\|remove> -name <name>` | **(Windows only)** Install or remove persistence via registry Run keys or startup folder. Supports HKCU/HKLM.
poolparty-injection | `poolparty-injection` | **(Windows only)** Inject shellcode using PoolParty techniques that abuse Windows Thread Pool internals. All 8 variants supported. [Details](research/injection-techniques.md#poolparty-injection)
port-scan | `port-scan -hosts <IPs/CIDRs> [-ports <ports>] [-timeout <s>]` | TCP connect scan for network service discovery. Supports CIDR, IP ranges, and port ranges. Cross-platform.
powershell | `powershell [command]` | **(Windows only)** Execute a PowerShell command or script directly via powershell.exe with -NoProfile -ExecutionPolicy Bypass.
ps | `ps [-v] [-i PID] [filter]` | List running processes. Use -v for verbose output with command lines. Use -i to filter by specific PID.
pwd | `pwd` | Print working directory.
read-memory | `read-memory <dll_name> <function_name> <start_index> <num_bytes>` | **(Windows only)** Read bytes from a DLL function address.
reg-read | `reg-read -hive <HIVE> -path <path> [-name <value>]` | **(Windows only)** Read a registry value or enumerate all values/subkeys under a key.
reg-write | `reg-write -hive <HIVE> -path <path> -name <name> -data <data> -type <type>` | **(Windows only)** Write a value to the Windows Registry. Creates keys if needed.
rev2self | `rev2self` | **(Windows only)** Revert to the original security context by dropping any active impersonation token.
rm | `rm <path>` | Remove a file or directory (recursively removes directories).
run | `run <command>` | Execute a shell command and return the output.
schtask | `schtask -action <create\|query\|delete\|run\|list> -name <name> [-program <path>]` | **(Windows only)** Create, query, run, or delete Windows scheduled tasks for persistence or execution.
screenshot | `screenshot` | **(Windows, macOS)** Capture a screenshot of the current desktop session. Captures all monitors and uploads as PNG. Uses GDI on Windows, screencapture on macOS.
service | `service -action <query\|start\|stop\|create\|delete\|list> -name <name> [-binpath <path>]` | **(Windows only)** Manage Windows services — query status, start, stop, create, or delete services.
setenv | `setenv -action <set\|unset> -name <NAME> [-value <VALUE>]` | Set or unset environment variables in the agent process. Cross-platform.
sleep | `sleep [seconds] [jitter] [working_start] [working_end] [working_days]` | Set callback interval, jitter, and working hours. Working hours restrict check-ins to specified times/days for opsec.
socks | `socks start [port]` / `socks stop [port]` | Start or stop a SOCKS5 proxy through the callback. Default port 7000. Tunnel tools like proxychains, nmap, or Impacket through the agent.
spawn | `spawn -path <exe> [-ppid <pid>] [-blockdlls true]` | **(Windows only)** Spawn a suspended process or thread for injection. Supports PPID spoofing (T1134.004) and non-Microsoft DLL blocking.
ssh-keys | `ssh-keys -action <list\|add\|remove\|read-private> [-key <ssh_key>] [-user <username>]` | **(Linux/macOS only)** Read or inject SSH authorized_keys. Read private keys for credential harvesting.
start-clr | `start-clr` | **(Windows only)** Initialize the CLR v4.0.30319 with optional AMSI/ETW patching (Ret Patch, Autopatch, or Hardware Breakpoint).
steal-token | `steal-token <pid>` | **(Windows only)** Steal and impersonate a security token from another process.
threadless-inject | `threadless-inject` | **(Windows only)** Inject shellcode using threadless injection by hooking a DLL function in a remote process. More stealthy than vanilla injection as it doesn't create new threads.
timestomp | `timestomp -action <get\|copy\|set> -target <file> [-source <file>] [-timestamp <time>]` | Modify file timestamps to blend in. Get, copy from another file, or set specific time. Windows also modifies creation time.
ts | `ts [-a] [-i PID]` | **(Windows only)** List threads in processes. By default shows only alertable threads (Suspended/DelayExecution). Use -a for all threads, -i to filter by PID (T1057).
upload | `upload` | Upload a file to the target with chunked file transfer.
vanilla-injection | `vanilla-injection` | **(Windows only)** Inject shellcode into a remote process using VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.
whoami | `whoami` | Display current user identity and security context. On Windows: username, SID, token type, integrity level, privileges. On Linux/macOS: user, UID, GID.
wmi | `wmi -action <execute\|query\|process-list\|os-info> [-target <host>] [-command <cmd>] [-query <wmic>]` | **(Windows only)** Execute WMI queries and process creation.
write-memory | `write-memory <dll_name> <function_name> <start_index> <hex_bytes>` | **(Windows only)** Write bytes to a DLL function address.

## Injection Techniques

### PoolParty Injection

| Variant | Technique | Trigger | Go Shellcode |
|---------|-----------|---------|--------------|
| 1 | Worker Factory Start Routine Overwrite | New worker thread creation | No |
| 2 | TP_WORK Insertion | Task queue processing | Yes |
| 3 | TP_WAIT Insertion | Event signaling | Yes |
| 4 | TP_IO Insertion | File I/O completion | Yes |
| 5 | TP_ALPC Insertion | ALPC port messaging | Yes |
| 6 | TP_JOB Insertion | Job object assignment | Yes |
| 7 | TP_DIRECT Insertion | I/O completion port | Yes |
| 8 | TP_TIMER Insertion | Timer expiration | Yes |

### Opus Injection

| Variant | Technique | Target | Go Shellcode |
|---------|-----------|--------|--------------|
| 1 | Ctrl-C Handler Chain | Console processes only | No |
| 4 | PEB KernelCallbackTable | GUI processes only | Yes |

For detailed variant descriptions, see [Injection Technique Details](research/injection-techniques.md).

## Build Options

### Binary Inflation

Fawkes supports optional binary inflation at build time. This embeds a block of repeated bytes into the compiled agent, which can be used to increase file size or lower entropy scores.

Two build parameters control this:
- **inflate_bytes** - Hex bytes to embed (e.g. `0x90` or `0x41,0x42`)
- **inflate_count** - Number of times to repeat the byte pattern

The byte pattern is repeated `inflate_count` times, so the total added size is `length(byte_pattern) * inflate_count`.

**Quick reference for sizing:**

| inflate_count | Single byte (e.g. `0x90`) | Two bytes (e.g. `0x41,0x42`) |
|---------------|---------------------------|------------------------------|
| 1,000 | 1 KB | 2 KB |
| 10,000 | 10 KB | 20 KB |
| 100,000 | 100 KB | 200 KB |
| 1,000,000 | 1 MB | 2 MB |
| 3,000,000 | 3 MB | 6 MB |
| 10,000,000 | 10 MB | 20 MB |

When inflation is not configured, only 1 byte of overhead is added to the binary.

## Opsec Features

### Artifact Tracking

Fawkes automatically registers artifacts with Mythic for opsec-relevant commands. Artifacts appear in the Mythic UI under the **Artifacts** tab, giving operators a clear picture of all forensic indicators generated during an engagement.

Tracked artifact types:

| Type | Commands |
|------|----------|
| Process Create | run, powershell, spawn, wmi, schtask, service, net-enum, net-shares |
| Process Kill | kill |
| Process Inject | vanilla-injection, apc-injection, threadless-inject, poolparty-injection, opus-injection |
| File Write | upload, cp, mv |
| File Create | mkdir |
| File Delete | rm |
| File Modify | timestomp |
| Registry Write | reg-write, persist (registry method) |
| Logon | make-token |
| Token Steal | steal-token |

Read-only commands (ls, ps, cat, env, etc.) do not generate artifacts.

### TLS Certificate Verification

Control how the agent validates HTTPS certificates when communicating with the C2 server. Configured at build time via the **tls_verify** parameter:

| Mode | Description |
|------|-------------|
| `none` | Skip all TLS verification (default, backward compatible) |
| `system-ca` | Validate certificates against the OS trust store |
| `pinned:<sha256>` | Pin to a specific certificate fingerprint (SHA-256 hex). Agent rejects connections if the server cert doesn't match. |

Certificate pinning prevents MITM interception of agent traffic even if an attacker controls a trusted CA.

### Domain Fronting

Set the **host_header** build parameter to override the HTTP `Host` header. This enables domain fronting: route traffic through a CDN (e.g., CloudFront, Azure CDN) while the `Host` header targets your actual C2 domain. To network defenders, the traffic appears to go to the CDN's IP address.

### Proxy Support

Set the **proxy_url** build parameter to route agent traffic through an HTTP or SOCKS proxy. Useful for operating in corporate networks with mandatory proxy servers.

Examples: `http://proxy.corp.local:8080`, `socks5://127.0.0.1:1080`

## Supported C2 Profiles

### [HTTP Profile](https://github.com/MythicC2Profiles/http)

The HTTP profile calls back to the Mythic server over the basic, non-dynamic profile.

## Thanks
Everything I know about Mythic Agents came from Mythic Docs or stealing code and ideas from the [Merlin](https://github.com/MythicAgents/merlin) and [Freyja](https://github.com/MythicAgents/freyja) agents.

After that, it's been exclusively feeding Claude PoC links and asking for cool stuff. Crazy right?

## Techniques and References
- **Threadless Injection** - [CCob's ThreadlessInject](https://github.com/CCob/ThreadlessInject) (original C# implementation) and [dreamkinn's go-ThreadlessInject](https://github.com/dreamkinn/go-ThreadlessInject) (Go port)
- **sRDI (Shellcode Reflective DLL Injection)** - [Merlin's Go-based sRDI implementation](https://github.com/MythicAgents/merlin), originally based on [Nick Landers' (monoxgas) sRDI](https://github.com/monoxgas/sRDI)
- **PoolParty Injection** - [SafeBreach Labs PoolParty research](https://github.com/SafeBreach-Labs/PoolParty) (original C++ PoC) - [Variant details](research/injection-techniques.md#poolparty-injection)
- **Opus Injection** - Callback-based injection techniques - [Variant details](research/injection-techniques.md#opus-injection)
- Phoenix icon from [OpenClipart](https://openclipart.org/detail/229408/colorful-phoenix-line-art-12)
