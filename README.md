# Fawkes Mythic C2 Agent

<img src="agent_icons/fawkes.svg" width="100" />

Fawkes is an entirely vibe-coded Mythic C2 agent. It started as an "I wonder" and has turned into a goal. My goal is to not write a single line of code for this agent, instead, exclusively producing it at a prompt.

I originally attempted to write the agent myself, but after cloning the example container, reading through mythic docs, watching the dev series youtube videos, and copying code from other agents like Merlin or Freyja, I decided I just didn't have time to develop my own agent. A prompt though, that I have time for.

Fawkes is a golang based agent with cross-platform capabilities. It supports **Windows** (EXE, DLL, and shellcode payloads), **Linux** (ELF binaries and shared libraries), and **macOS** (Mach-O binaries for Intel and Apple Silicon). 55 commands are cross-platform, with 48 additional Windows-only commands, 1 Windows+macOS command (screenshot), 3 Unix-only commands, 6 Linux-only commands, and 2 macOS-only commands for a total of 116. Supports HTTP egress and TCP peer-to-peer (P2P) linking for internal pivoting.

## Installation
To install Fawkes, you'll need Mythic installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install directory:

```
./mythic-cli install github https://github.com/galoryber/fawkes
```

## Commands Quick Reference

Command | Syntax | Description
------- | ------ | -----------
adcs | `adcs -action <cas\|templates\|find> -server <DC> -username <user@domain> -password <pass>` | Enumerate AD Certificate Services and find vulnerable templates (ESC1-ESC4). Includes security descriptor parsing for enrollment permissions. Cross-platform (T1649).
apc-injection | `apc-injection` | **(Windows only)** Perform QueueUserAPC injection into an alertable thread. Use `ts` to find alertable threads (T1055.004).
arp | `arp` | Display ARP table — shows IP-to-MAC address mappings for nearby hosts. Cross-platform.
asrep-roast | `asrep-roast -server <DC> -username <user@domain> -password <pass> [-account <target>]` | Request AS-REP tickets for accounts without pre-authentication and extract hashes in hashcat format for offline cracking. Auto-enumerates via LDAP. Cross-platform (T1558.004).
av-detect | `av-detect` | Detect installed AV/EDR/security products by scanning running processes against a 130+ signature database. Reports product, vendor, type, and PID. Cross-platform.
autopatch | `autopatch <dll_name> <function_name> <num_bytes>` | **(Windows only)** Automatically patch a function by jumping to nearest return (C3) instruction. Useful for AMSI/ETW bypasses.
browser | `browser [-action <passwords>] [-browser <all\|chrome\|edge>]` | **(Windows only)** Harvest saved credentials from Chromium-based browsers (Chrome, Edge) via DPAPI + AES-GCM decryption. MITRE T1555.003.
cat | `cat <file>` | Display the contents of a file.
cd | `cd <directory>` | Change the current working directory.
clipboard | `clipboard -action <read\|write\|monitor\|dump\|stop> [-data "text"] [-interval 3]` | **(Windows only)** Read/write clipboard or continuously monitor for changes with credential pattern detection (T1115).
compress | `compress -action <create\|list\|extract> -path <path> [-output <out>] [-pattern *.txt]` | Create, list, or extract zip archives for data staging and exfiltration. Pattern filter, depth/size limits. Cross-platform (T1560.001).
cp | `cp <source> <destination>` | Copy a file from source to destination.
cred-harvest | `cred-harvest -action <shadow\|cloud\|configs\|windows\|all> [-user <username>]` | Harvest credentials: shadow hashes (Unix), cloud configs (AWS/GCP/Azure/K8s), application secrets, PowerShell history + env vars + RDP (Windows). Cross-platform (T1552.001, T1552.004, T1003.008).
curl | `curl -url <URL> [-method GET\|POST\|PUT\|DELETE\|HEAD\|OPTIONS\|PATCH] [-headers '{"K":"V"}'] [-body <data>] [-output full\|body\|headers]` | Make HTTP/HTTPS requests from agent's network. Cloud metadata, internal services, SSRF. Cross-platform (T1106).
credman | `credman [-action <list\|dump>] [-filter <pattern>]` | **(Windows only)** Enumerate Windows Credential Manager entries. `list` shows metadata, `dump` reveals passwords. MITRE T1555.004.
defender | `defender -action <status\|exclusions\|add-exclusion\|remove-exclusion\|threats> [-type <path\|process\|extension>] [-value <val>]` | **(Windows only)** Query Defender status, manage exclusions, view threat history. WMI + registry. MITRE T1562.001.
dcom | `dcom -action exec -host <target> -command <cmd> [-args <arguments>] [-object mmc20\|shellwindows\|shellbrowser]` | **(Windows only)** Execute commands on remote hosts via DCOM lateral movement. Three objects: MMC20.Application, ShellWindows, ShellBrowserWindow. MITRE T1021.003.
dcsync | `dcsync -server <DC> -username <user> [-password <pass>] [-hash <NT hash>] -target <account[,account2]>` | DCSync — replicate AD credentials via DRS without touching LSASS. Extracts NTLM hashes, Kerberos keys (AES256/AES128). Supports pass-the-hash. Cross-platform (T1003.006).
dns | `dns -action <resolve\|reverse\|srv\|mx\|ns\|txt\|cname\|all\|dc\|zone-transfer> -target <host> [-server <dns_ip>]` | DNS enumeration — resolve hosts, query records, discover domain controllers, zone transfers (AXFR). Cross-platform (T1018).
drivers | `drivers [-filter <name>]` | Enumerate loaded kernel drivers/modules. Windows: EnumDeviceDrivers, Linux: /proc/modules, macOS: kext enumeration. Cross-platform (T1082).
domain-policy | `domain-policy -action <all\|password\|lockout\|fgpp> -server <DC> -username <user@domain> -password <pass>` | AD password/lockout policy and FGPP enumeration via LDAP. Spray-safe recommendations. Cross-platform (T1201).
crontab | `crontab -action <list\|add\|remove> [-entry <cron_line>] [-program <path>] [-schedule <schedule>]` | **(Linux/macOS only)** List, add, or remove cron jobs for persistence. Supports raw cron entries or program+schedule syntax.
download | `download <path>` | Download a file from the target. Supports chunked file transfer for any file size and file browser integration.
drives | `drives` | **(Windows only)** List available drives/volumes with type (Fixed/Removable/Network/CD-ROM), label, and free/total space.
enum-tokens | `enum-tokens [-action list\|unique] [-user <filter>]` | **(Windows only)** Enumerate access tokens across all processes. `list` shows PID/user/integrity/session for each process. `unique` groups by user with process counts. Auto-enables SeDebugPrivilege (T1134, T1057).
env | `env [filter]` | List environment variables. Optionally filter by name (case-insensitive).
eventlog | `eventlog -action <list\|query\|clear\|info> [-channel <name>] [-event_id <id>] [-filter <xpath>] [-count <max>]` | **(Windows only)** Manage Windows Event Logs via wevtapi.dll. List channels, query events (XPath/EventID/time filtering), clear logs, get channel info. MITRE T1070.001.
exit | `exit` | Task agent to exit.
find | `find -pattern <glob> [-path <dir>] [-max_depth <n>]` | Search for files by name pattern. Cross-platform recursive file search with depth limit.
firewall | `firewall -action <list\|add\|delete\|enable\|disable\|status> [-name <rule>] [-direction <in\|out>] [-protocol <tcp\|udp\|any>] [-port <port>]` | **(Windows only)** Manage Windows Firewall rules via COM API. List/filter rules, add/delete rules, enable/disable rules, check profile status. MITRE T1562.004.
getprivs | `getprivs` | **(Windows only)** List all privileges of the current token with enabled/disabled status, descriptions, and integrity level (T1078).
getsystem | `getsystem [-technique steal]` | **(Windows only)** Elevate to SYSTEM by stealing a token from a SYSTEM process (winlogon.exe). Requires admin/SeDebugPrivilege (T1134.001).
gpo | `gpo -action <list\|links\|find\|all> -server <DC> -username <user@domain> -password <pass> [-filter <name>]` | Enumerate Group Policy Objects via LDAP — list GPOs, map links with enforcement, find interesting CSE settings. Cross-platform (T1615).
grep | `grep -pattern <regex> [-path <dir>] [-extensions .txt,.xml] [-ignore_case] [-max_results 100]` | Search file contents for regex patterns. Recursive directory search with extension filtering, context lines, and binary file skipping. Cross-platform (T1083, T1552.001).
handles | `handles -pid <pid> [-type File] [-show_names] [-max_count 500]` | **(Windows only)** Enumerate open handles in a process via NtQuerySystemInformation. Type summary, name resolution, type filtering (T1057, T1082).
hashdump | `hashdump` | **(Windows only)** Extract local account NTLM hashes from the SAM database. Uses registry backup semantics to bypass DACLs. Output format: user:RID:LM:NT:::. Requires admin. MITRE T1003.002.
ifconfig | `ifconfig` | List network interfaces with addresses, MAC, MTU, and flags. Cross-platform (Windows/Linux/macOS).
inline-assembly | `inline-assembly` | **(Windows only)** Execute a .NET assembly in memory using the CLR. Supports command-line arguments. Use `start-clr` first for AMSI patching workflow.
inline-execute | `inline-execute` | **(Windows only)** Execute a Beacon Object File (BOF/COFF) in memory. Supports all argument types: strings (z), wide strings (Z), integers (i), shorts (s), and binary (b).
iptables | `iptables -action <status\|rules\|nat\|add\|delete\|flush> [-rule <args>] [-table <name>]` | **(Linux only)** Linux firewall enumeration and management via iptables/nftables/ufw. IP forwarding, connection tracking, rule listing and modification. MITRE T1562.004.
kerberoast | `kerberoast -server <DC> -username <user@domain> -password <pass> [-spn <SPN>]` | Request TGS tickets for SPN accounts and extract hashes in hashcat format for offline cracking. Auto-enumerates via LDAP. Cross-platform (T1558.003).
klist | `klist -action <list\|purge\|dump\|import> [-server <filter>] [-ticket <base64>] [-path <path>]` | Enumerate, dump, purge, and import Kerberos tickets. Import enables Pass-the-Ticket: Windows injects kirbi via LSA, Linux/macOS writes ccache + sets KRB5CCNAME. Cross-platform (T1558, T1550.003).
keychain | `keychain -action <list\|dump\|find-password\|find-internet\|find-cert> [-service <name>] [-server <host>]` | **(macOS only)** Access macOS Keychain — list keychains, dump metadata, find generic/internet passwords, enumerate certificates.
kerb-delegation | `kerb-delegation -action <all\|unconstrained\|constrained\|rbcd> -server <DC> -username <user@domain> -password <pass>` | Enumerate Kerberos delegation relationships — unconstrained, constrained (with protocol transition), RBCD. Detects sensitive accounts. Cross-platform (T1550.003).
keylog | `keylog -action <start\|stop\|dump>` | **(Windows only)** Low-level keyboard logger with window context. Start/stop/dump captured keystrokes.
ldap-query | `ldap-query -action <users\|computers\|groups\|domain-admins\|spns\|asrep\|query> -server <DC>` | Query Active Directory via LDAP. Preset queries for users, computers, groups, domain admins, SPNs, AS-REP roastable accounts, or custom LDAP filters. Cross-platform (T1087.002).
kill | `kill -pid <PID>` | Terminate a process by PID. Cross-platform (Windows/Linux/macOS).
laps | `laps -server <DC> -username <user@domain> -password <pass> [-filter <computer>]` | Read LAPS passwords from AD via LDAP. Supports LAPS v1 (ms-Mcs-AdmPwd) and Windows LAPS v2 (ms-LAPS-Password). Cross-platform (T1552.006).
launchagent | `launchagent -action <install\|remove\|list> -label <com.example.name> [-path <exe>] [-daemon true]` | **(macOS only)** Install, remove, or list LaunchAgent/LaunchDaemon persistence. Creates plist with RunAtLoad+KeepAlive.
link | `link -host <ip> -port <port>` | Link to a TCP P2P agent for internal pivoting. Target agent must be built with TCP profile. Cross-platform (T1572).
linux-logs | `linux-logs -action <list\|read\|logins\|clear\|truncate\|shred> [-file <path>] [-search <filter>] [-lines <n>]` | **(Linux only)** List, read, clear, or tamper with Linux log files and binary login records (wtmp/btmp/utmp). Supports selective line removal and secure shredding (T1070.002).
logonsessions | `logonsessions [-action list\|users] [-filter <name>]` | **(Windows only)** Enumerate active logon sessions — users, session IDs, stations, connection state. Filter by username/domain.
ls | `ls [path]` | List files and folders with owner/group and timestamps. File browser integration. Defaults to cwd.
make-token | `make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]` | **(Windows only)** Create a token from credentials and impersonate it.
mkdir | `mkdir <directory>` | Create a new directory (creates parent directories if needed).
modules | `modules [-pid <PID>]` | List loaded modules/DLLs/libraries in a process. Windows: CreateToolhelp32Snapshot. Linux: /proc/pid/maps. macOS: proc_info syscall. Default: current process. Cross-platform (T1057).
mv | `mv <source> <destination>` | Move or rename a file from source to destination.
named-pipes | `named-pipes [-filter <pattern>]` | **(Windows only)** List named pipes on the system for IPC discovery and pipe-based privilege escalation recon. Supports substring filtering (T1083).
net-enum | `net-enum -action <users\|localgroups\|groupmembers\|domainusers\|domaingroups\|domaininfo> [-target <group>]` | **(Windows only)** Enumerate local/domain users, groups, and domain info via Win32 API (no subprocess).
net-group | `net-group -action <list\|members\|user\|privileged> -server <DC> [-group <name>] [-user <sAMAccountName>] -username <user@domain> -password <pass>` | Enumerate AD group memberships via LDAP. Recursive member resolution, user group lookup, privileged group enumeration. Cross-platform (T1069.002).
net-shares | `net-shares -action <local\|remote\|mapped> [-target <host>]` | **(Windows only)** Enumerate network shares and mapped drives via Win32 API (no subprocess).
net-user | `net-user -action <add\|delete\|info\|password\|group-add\|group-remove> -username <name> [-password <pass>] [-group <group>]` | **(Windows only)** Manage local user accounts and group membership via netapi32 API. MITRE T1136.001, T1098.
net-stat | `net-stat` | List active network connections and listening ports with protocol, state, and PID. Cross-platform.
ntdll-unhook | `ntdll-unhook [-action unhook\|check]` | **(Windows only)** Remove EDR inline hooks from ntdll.dll by restoring the .text section from a clean on-disk copy. `check` reports hooks without removing them (T1562.001).
opus-injection | `opus-injection` | **(Windows only)** Callback-based process injection. Variant 1: Ctrl-C Handler Chain. Variant 4: PEB KernelCallbackTable. [Details](research/injection-techniques.md#opus-injection)
persist | `persist -method <registry\|startup-folder\|com-hijack\|screensaver\|list> -action <install\|remove>` | **(Windows only)** Install or remove persistence via registry Run keys, startup folder, COM hijacking (T1546.015), or screensaver hijacking (T1546.002). No admin for HKCU methods.
poolparty-injection | `poolparty-injection` | **(Windows only)** Inject shellcode using PoolParty techniques that abuse Windows Thread Pool internals. All 8 variants supported. [Details](research/injection-techniques.md#poolparty-injection)
port-scan | `port-scan -hosts <IPs/CIDRs> [-ports <ports>] [-timeout <s>]` | TCP connect scan for network service discovery. Supports CIDR, IP ranges, and port ranges. Cross-platform.
powershell | `powershell [command]` | **(Windows only)** Execute a PowerShell command or script directly via powershell.exe with -NoProfile -ExecutionPolicy Bypass.
privesc-check | `privesc-check -action <all\|suid\|capabilities\|sudo\|writable\|container>` | **(Linux only)** Privilege escalation enumeration: SUID/SGID binaries, file capabilities, sudo rules, writable PATH dirs, container detection. MITRE T1548.
psexec | `psexec -host <target> -command <cmd> [-name <svcname>] [-cleanup <true\|false>]` | **(Windows only)** Execute commands on remote hosts via SCM service creation — PSExec-style lateral movement. MITRE T1021.002, T1569.002.
proc-info | `proc-info -action <info\|connections\|mounts\|modules> [-pid <PID>]` | **(Linux only)** Deep /proc inspection: process details (cmdline, env, caps, cgroups, namespaces, FDs), network connections with PID resolution, mounts, kernel modules. MITRE T1057.
procdump | `procdump [-action lsass\|dump] [-pid <PID>]` | **(Windows only)** Dump process memory via MiniDumpWriteDump. Auto-finds lsass.exe or dump any process by PID. Uploads to Mythic and cleans from disk. PPL detection. MITRE T1003.001.
ps | `ps [-v] [-i PID] [filter]` | List running processes with Mythic process browser integration. Supports PID filtering, name search, and clickable table UI. Cross-platform.
ptrace-inject | `ptrace-inject -action <check\|inject> [-pid <PID>] [-filename <shellcode>] [-restore <true>] [-timeout <30>]` | **(Linux only, x86_64)** Process injection via ptrace — PTRACE_ATTACH/POKETEXT/SETREGS with register and code restore. Check mode reports ptrace_scope, capabilities, and candidates (T1055.008).
pwd | `pwd` | Print working directory.
read-memory | `read-memory <dll_name> <function_name> <start_index> <num_bytes>` | **(Windows only)** Read bytes from a DLL function address.
reg-delete | `reg-delete -hive <HIVE> -path <path> [-name <value>] [-recursive <true>]` | **(Windows only)** Delete a registry value, key, or key tree (recursive). MITRE T1112.
reg-read | `reg-read -hive <HIVE> -path <path> [-name <value>]` | **(Windows only)** Read a registry value or enumerate all values/subkeys under a key.
reg-write | `reg-write -hive <HIVE> -path <path> -name <name> -data <data> -type <type>` | **(Windows only)** Write a value to the Windows Registry. Creates keys if needed.
rev2self | `rev2self` | **(Windows only)** Revert to the original security context by dropping any active impersonation token.
route | `route` | Display the system routing table. Windows: GetIpForwardTable API, Linux: /proc/net/route + IPv6, macOS: netstat -rn. Cross-platform (T1016).
rpfwd | `rpfwd start <port> <remote_ip> <remote_port>` / `rpfwd stop <port>` | Reverse port forward -- agent listens, Mythic routes to target. Cross-platform (T1090).
rm | `rm <path>` | Remove a file or directory (recursively removes directories).
run | `run <command>` | Execute a shell command and return the output.
schtask | `schtask -action <create\|query\|delete\|run\|list> -name <name> [-program <path>]` | **(Windows only)** Create, query, run, or delete Windows scheduled tasks via COM API.
screenshot | `screenshot` | **(Windows, macOS)** Capture a screenshot of the current desktop session. Captures all monitors and uploads as PNG. Uses GDI on Windows, screencapture on macOS.
smb | `smb -action <shares\|ls\|cat\|upload\|rm> -host <target> -username <user> [-password <pass>] [-hash <NT hash>] [-share <name>] [-path <path>]` | SMB2 file operations on remote shares — list shares, browse directories, read/write/delete files. NTLM auth with pass-the-hash support. Cross-platform (T1021.002, T1550.002).
service | `service -action <query\|start\|stop\|create\|delete\|list> -name <name> [-binpath <path>]` | **(Windows only)** Manage Windows services via SCM API (no subprocess).
setenv | `setenv -action <set\|unset> -name <NAME> [-value <VALUE>]` | Set or unset environment variables in the agent process. Cross-platform.
shell-config | `shell-config -action <history\|list\|read\|inject\|remove> [-file <.bashrc>] [-line <cmd>] [-lines <count>]` | **(Linux/macOS only)** Read shell history, list/read/inject/remove shell config files. Persistence via .bashrc/.zshrc + credential harvesting from history. MITRE T1546.004, T1552.003.
sleep | `sleep [seconds] [jitter] [working_start] [working_end] [working_days]` | Set callback interval, jitter, and working hours. Working hours restrict check-ins to specified times/days for opsec.
socks | `socks start [port]` / `socks stop [port]` | Start or stop a SOCKS5 proxy through the callback. Default port 7000. Tunnel tools like proxychains, nmap, or Impacket through the agent.
spawn | `spawn -path <exe> [-ppid <pid>] [-blockdlls true]` | **(Windows only)** Spawn a suspended process or thread for injection. Supports PPID spoofing (T1134.004) and non-Microsoft DLL blocking.
spray | `spray -action <kerberos\|ldap\|smb> -server <DC> -domain <DOMAIN> -users <user1\nuser2> [-password <pass>] [-hash <NT hash>] [-delay <ms>] [-jitter <0-100>]` | Password spray against AD via Kerberos pre-auth, LDAP bind, or SMB auth. SMB supports pass-the-hash. Lockout-aware with configurable delay/jitter. Cross-platform (T1110.003, T1550.002).
ssh | `ssh -host <target> -username <user> [-password <pass>] [-key_path <path>] [-key_data <pem>] -command <cmd>` | Execute commands on remote hosts via SSH. Password, key file, or inline key auth. Cross-platform lateral movement (T1021.004).
ssh-keys | `ssh-keys -action <list\|add\|remove\|read-private> [-key <ssh_key>] [-user <username>]` | **(Linux/macOS only)** Read or inject SSH authorized_keys. Read private keys for credential harvesting.
start-clr | `start-clr` | **(Windows only)** Initialize the CLR v4.0.30319 with optional AMSI/ETW patching (Ret Patch, Autopatch, or Hardware Breakpoint).
systemd-persist | `systemd-persist -action <install\|remove\|list> -name <unit> [-exec_start <cmd>] [-timer <calendar>] [-system true]` | **(Linux only)** Install, remove, or list systemd service/timer persistence. User or system scope. MITRE T1543.002.
steal-token | `steal-token <pid>` | **(Windows only)** Steal and impersonate a security token from another process.
sysinfo | `sysinfo` | Comprehensive system information: OS version, hardware, memory, uptime, domain, .NET (Windows), SELinux/SIP status. Cross-platform (T1082).
threadless-inject | `threadless-inject` | **(Windows only)** Inject shellcode using threadless injection by hooking a DLL function in a remote process. More stealthy than vanilla injection as it doesn't create new threads.
ticket | `ticket -action forge\|request\|s4u -realm <DOMAIN> -username <user> -key <hex_key> [-key_type aes256\|aes128\|rc4] [-format kirbi\|ccache] [-domain_sid <SID>] [-spn <SPN>] [-server <KDC>] [-impersonate <user>]` | Forge, request, or delegate Kerberos tickets. Forge: Golden/Silver Tickets (offline). Request: Overpass-the-Hash (online). S4U: constrained delegation abuse via S4U2Self+S4U2Proxy. Cross-platform (T1558.001, T1558.002, T1550.002, T1134.001).
trust | `trust -server <DC> -username <user@domain> -password <pass> [-use_tls]` | Enumerate domain and forest trust relationships via LDAP. Identifies trust direction, type, SID filtering, and attack paths. Cross-platform (T1482).
timestomp | `timestomp -action <get\|copy\|set> -target <file> [-source <file>] [-timestamp <time>]` | Modify file timestamps to blend in. Get, copy from another file, or set specific time. Windows also modifies creation time.
ts | `ts [-a] [-i PID]` | **(Windows only)** List threads in processes. By default shows only alertable threads (Suspended/DelayExecution). Use -a for all threads, -i to filter by PID (T1057).
uac-bypass | `uac-bypass [-technique fodhelper\|computerdefaults\|sdclt] [-command <path>]` | **(Windows only)** Bypass UAC to escalate from medium to high integrity. Registry-based hijack + auto-elevating binary. Default spawns elevated callback (T1548.002).
unlink | `unlink -connection_id <uuid>` | Disconnect a linked TCP P2P agent. Cross-platform (T1572).
upload | `upload` | Upload a file to the target with chunked file transfer.
vanilla-injection | `vanilla-injection` | **(Windows only)** Inject shellcode into a remote process using VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.
vss | `vss -action <list\|create\|delete\|extract> [-volume C:\\] [-id <device_path>] [-source <path>] [-dest <path>]` | **(Windows only)** Manage Volume Shadow Copies — list, create, delete, extract files. Extract locked files (NTDS.dit, SAM) without touching lsass. MITRE T1003.003.
winrm | `winrm -host <target> -username <user> [-password <pass>] [-hash <NT hash>] -command <cmd> [-shell cmd\|powershell]` | Execute commands on remote Windows hosts via WinRM with NTLM authentication. Supports pass-the-hash, cmd.exe and PowerShell. Cross-platform (T1021.006, T1550.002).
whoami | `whoami` | Display current user identity and security context. On Windows: username, SID, token type, integrity level, group memberships, privileges. On Linux/macOS: user, UID, GID, supplementary groups.
wmi | `wmi -action <execute\|query\|process-list\|os-info> [-target <host>] [-command <cmd>] [-query <wql>]` | **(Windows only)** Execute WMI queries and process creation via COM API.
wmi-persist | `wmi-persist -action <install\|remove\|list> -name <id> -trigger <logon\|startup\|interval\|process> -command <exe>` | **(Windows only)** WMI Event Subscription persistence via COM API. Fileless, survives reboots. MITRE T1546.003.
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
| Process Create | run, powershell, spawn |
| API Call | net-enum, net-shares, net-user, service, wmi, schtask, procdump, hashdump, eventlog, ntdll-unhook, firewall, dcom, vss (create/delete), psexec |
| Process Kill | kill |
| Process Inject | vanilla-injection, apc-injection, threadless-inject, poolparty-injection, opus-injection |
| File Write | upload, cp, mv |
| File Create | mkdir |
| File Delete | rm |
| File Modify | timestomp |
| Registry Write | reg-write, reg-delete, persist (registry, com-hijack, screensaver methods), uac-bypass, defender (add/remove-exclusion) |
| Logon | make-token |
| Token Steal | steal-token, getsystem |

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

The HTTP profile calls back to the Mythic server over the basic, non-dynamic profile. This is the default egress profile — the agent polls Mythic for tasking over HTTP/HTTPS.

### TCP P2P Profile

The TCP profile enables peer-to-peer (P2P) agent linking for internal pivoting. A TCP child agent listens on a port and waits for a parent agent to connect via the `link` command. All tasking and responses are routed through the parent's egress channel (HTTP), so the child never contacts Mythic directly.

**Architecture:**

```
Mythic Server ←──HTTP──→ Egress Agent (HTTP profile)
                              │
                              ├──TCP──→ Child Agent A (TCP profile, port 7777)
                              └──TCP──→ Child Agent B (TCP profile, port 8888)
```

**Build parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tcp_bind_address` | Address and port for the child to listen on (e.g., `0.0.0.0:7777`) | _(empty = HTTP mode)_ |

When `tcp_bind_address` is set, the agent starts in TCP listener mode instead of HTTP egress mode. The TCP C2 profile parameters (port, AESPSK, killdate) configure the listener.

**Usage workflow:**

1. Build a **child agent** with the TCP C2 profile and `tcp_bind_address` set (e.g., `0.0.0.0:7777`)
2. Deploy the child to an internal host (no internet access required)
3. From an **egress agent** (HTTP profile), run: `link -host <child_ip> -port 7777`
4. Mythic creates a new callback for the child — all tasking flows through the egress agent
5. To disconnect: `unlink -connection_id <uuid>`

**Encryption:** AES-256-CBC with HMAC-SHA256 (same as HTTP profile). Wire protocol uses 4-byte length-prefixed framing.

**Relink support:** If a parent disconnects (e.g., via `unlink` or parent agent dies), the child agent caches its checkin data and waits for a new parent connection. When a new egress agent runs `link`, the child automatically re-registers with Mythic as a new callback. No manual intervention needed.

**Multiple children:** An egress agent can link to multiple TCP children simultaneously. Each child operates independently with its own callback.

## Thanks
Everything I know about Mythic Agents came from Mythic Docs or stealing code and ideas from the [Merlin](https://github.com/MythicAgents/merlin) and [Freyja](https://github.com/MythicAgents/freyja) agents.

After that, it's been exclusively feeding Claude PoC links and asking for cool stuff. Crazy right?

## Techniques and References
- **Threadless Injection** - [CCob's ThreadlessInject](https://github.com/CCob/ThreadlessInject) (original C# implementation) and [dreamkinn's go-ThreadlessInject](https://github.com/dreamkinn/go-ThreadlessInject) (Go port)
- **sRDI (Shellcode Reflective DLL Injection)** - [Merlin's Go-based sRDI implementation](https://github.com/MythicAgents/merlin), originally based on [Nick Landers' (monoxgas) sRDI](https://github.com/monoxgas/sRDI)
- **PoolParty Injection** - [SafeBreach Labs PoolParty research](https://github.com/SafeBreach-Labs/PoolParty) (original C++ PoC) - [Variant details](research/injection-techniques.md#poolparty-injection)
- **Opus Injection** - Callback-based injection techniques - [Variant details](research/injection-techniques.md#opus-injection)
- Phoenix icon from [OpenClipart](https://openclipart.org/detail/229408/colorful-phoenix-line-art-12)
