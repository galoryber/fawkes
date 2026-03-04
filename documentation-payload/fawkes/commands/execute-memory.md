+++
title = "execute-memory"
chapter = false
weight = 100
hidden = false
+++

## Summary

Execute a native binary from memory with zero or minimal disk artifacts. Auto-detects PE type on Windows and selects the optimal execution method.

{{% notice info %}}Cross-Platform: Windows, Linux, macOS{{% /notice %}}

## How It Works

### Windows — Smart PE Dispatcher
The command auto-detects the PE type and selects the best execution method:

**1. .NET Assemblies** (detected via CLR header in data directory[14]):
- Routes to CLR hosting path (same as `inline-assembly`)
- Assembly.Load() + entry point invocation — zero disk artifacts
- Auto-starts CLR v4 if not already initialized
- Tip: run `start-clr` with Autopatch first for AMSI bypass

**2. Native EXEs** (in-memory PE mapping):
1. Manual section mapping: headers, sections, BSS zeroing
2. Base relocation processing (DIR64 for x64)
3. Import resolution with IAT-level ExitProcess → ExitThread hook (prevents agent death)
4. W^X section protections + instruction cache flush
5. TLS callback invocation (required by C/C++ executables using thread-local storage)
6. PEB CommandLine patching (GetCommandLineW returns operator-specified args, not agent path)
7. Thread-based execution with stdout/stderr capture via pipes
8. Timeout enforcement with thread termination
9. Falls back to temp file if in-memory mapping fails

**3. Native DLLs** (reflective loading):
1. Same PE mapping pipeline as EXEs
2. TLS callbacks invoked before DllMain
3. Calls DllMain(DLL_PROCESS_ATTACH) instead of creating a thread
4. Zero disk artifacts

### Linux (memfd_create)
1. `memfd_create("")` creates an anonymous file backed by memory
2. The ELF binary is written to this memory file descriptor
3. The binary is executed via `/proc/<pid>/fd/<fd>` path
4. stdout/stderr are captured and returned
5. The memfd is closed and the memory is freed

No file is ever written to disk — the binary exists only in an anonymous memory-backed file descriptor.

### macOS (temp file + codesign)
1. A temp file is created in the system temp directory
2. The Mach-O binary is written and made executable
3. Ad-hoc code signing is applied (`codesign -s -`) — required on Apple Silicon (arm64)
4. The binary is executed with timeout enforcement
5. The temp file is removed immediately after execution completes

The temp file exists only for the duration of execution. Apple Silicon requires code signatures at runtime.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| file/filename/binary_b64 | Yes | The native binary to execute (upload, select existing, or base64-encode) |
| arguments | No | Command-line arguments to pass to the binary |
| timeout | No | Execution timeout in seconds (default: 60) |
| export_name | No | Windows DLLs only: export function to call after DllMain (e.g., Go, Run, Execute) |

## Usage

**Via Mythic UI:** Upload a native binary (PE for Windows, ELF for Linux, Mach-O for macOS) or select a previously uploaded one, optionally provide arguments.

**Via CLI/API:**
```
execute-memory -binary_b64 <base64_binary> -arguments "-h" -timeout 30
```

## Examples

Execute a static binary from memory:
```
execute-memory (upload file via UI) -arguments "--scan 192.168.1.0/24"
```

Execute with timeout:
```
execute-memory (upload file via UI) -arguments "-v" -timeout 120
```

## Notes

- **Windows:** Auto-detects .NET (CLR header) vs native PE. Native EXEs use in-memory mapping with ExitProcess hooking, PEB command line patching, and TLS callback support — no temp file, no disk IOCs. Falls back to temp file if in-memory loading fails (e.g., complex dependencies).
- **Linux:** Binary must be a valid ELF executable (magic bytes validated). Requires kernel 3.17+ for memfd_create. Binary appears in `ps` as `/proc/<pid>/fd/<N>` or `memfd:`.
- **macOS:** Binary must be a valid Mach-O executable (all 6 magic variants validated). Ad-hoc codesign is applied automatically — required on Apple Silicon.
- Static binaries work best — dynamically linked binaries require shared libraries on the target
- Maximum binary size is limited by available memory
- For .NET assemblies, `start-clr` with AMSI patching is recommended before execution

## MITRE ATT&CK Mapping

- **T1620** — Reflective Code Loading
