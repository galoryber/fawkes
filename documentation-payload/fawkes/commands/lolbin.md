+++
title = "lolbin"
chapter = false
weight = 221
hidden = false
+++

## Summary

Signed binary proxy execution — execute payloads through legitimate Windows binaries (LOLBins) to bypass application whitelisting, SmartScreen, and some EDR detections. Each technique leverages a Microsoft-signed binary to load or execute arbitrary code.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | — | LOLBin technique to use (see techniques table) |
| path | Yes | — | Path to the payload file |
| export | No | DllMain | DLL export function name (rundll32 only) |
| args | No | — | Additional arguments for the LOLBin |

### Techniques

| Action | Binary | ATT&CK | Description |
|--------|--------|--------|-------------|
| rundll32 | rundll32.exe | T1218.011 | Execute DLL export functions |
| msiexec | msiexec.exe | T1218.007 | Install/execute MSI packages silently |
| regsvcs | RegSvcs.exe | T1218.009 | .NET COM component registration |
| regasm | RegAsm.exe | T1218.009 | .NET assembly registration |
| mshta | mshta.exe | T1218.005 | Execute HTA/JavaScript/VBScript |
| certutil | certutil.exe | T1218 | Decode base64-encoded payloads |

## Usage

```
# Execute a DLL export via rundll32
lolbin -action rundll32 -path C:\payload.dll -export Run

# Install MSI silently
lolbin -action msiexec -path C:\payload.msi

# .NET assembly via RegSvcs
lolbin -action regsvcs -path C:\payload.dll

# .NET assembly via RegAsm
lolbin -action regasm -path C:\payload.dll

# Execute HTA file
lolbin -action mshta -path C:\payload.hta

# Decode base64 file via certutil
lolbin -action certutil -path C:\encoded.b64
```

## Operational Notes

- All techniques use Microsoft-signed binaries already present on Windows
- Command-line arguments are visible in process creation logs (Sysmon EID 1)
- Some EDR products specifically monitor child processes of common LOLBins
- `rundll32` is the most commonly used and most commonly monitored
- `regsvcs`/`regasm` require .NET Framework (present on most Windows systems)
- Use with `masquerade` command to disguise payload files before execution

## MITRE ATT&CK Mapping

- **T1218** — Signed Binary Proxy Execution
- **T1218.011** — Rundll32
- **T1218.007** — Msiexec
- **T1218.009** — Regsvcs/Regasm
- **T1218.005** — Mshta
