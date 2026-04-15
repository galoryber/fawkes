+++
title = "ptrace-inject"
chapter = false
weight = 112
hidden = false
+++

## Summary

Linux process injection via the ptrace syscall. Attaches to a target process, writes shellcode into an executable memory region, redirects execution, and optionally restores the original code and registers after completion. Includes a configuration check mode that reports ptrace scope, capabilities, and candidate processes.

{{% notice info %}}Linux Only (x86_64){{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `check`: report ptrace config. `inject`: shellcode injection. `ld-preload`: list LD_PRELOAD settings. `ld-install`: install LD_PRELOAD persistence. `ld-remove`: remove LD_PRELOAD entry. |
| pid | Inject | Target process ID to inject into |
| filename | Inject (UI) | Select shellcode file from Mythic's file storage |
| file | Inject (UI) | Upload a new shellcode file |
| shellcode_b64 | Inject (CLI) | Base64-encoded shellcode (for API/CLI usage) |
| restore | No | Restore original code and registers after execution (default: true) |
| timeout | No | Timeout in seconds waiting for shellcode completion (default: 30) |
| libpath | ld-install/ld-remove | Path to shared library for LD_PRELOAD |
| target | ld-install/ld-remove | Target file: auto, ld.so.preload, bashrc, profile, zshrc, etc. |

## Usage

```
# Check ptrace configuration, capabilities, and candidate processes
ptrace-inject -action check

# Inject shellcode from Mythic file storage into a target process
ptrace-inject -action inject -pid 1234 -filename shellcode.bin

# Inject with upload (via Mythic UI)
ptrace-inject -action inject -pid 1234 -file <upload>

# Fire-and-forget injection (no restore)
ptrace-inject -action inject -pid 1234 -filename shellcode.bin -restore false

# Custom timeout
ptrace-inject -action inject -pid 1234 -filename shellcode.bin -timeout 60
```

## Injection Process

1. **PTRACE_ATTACH** — Attach to the target process (sends SIGSTOP)
2. **PTRACE_GETREGS** — Save the original register state (RIP, RSP, etc.)
3. **Find executable region** — Parse `/proc/<pid>/maps` for an r-xp memory region (skips vdso/vsyscall)
4. **PTRACE_PEEKTEXT** — Backup the original code at the injection point
5. **PTRACE_POKETEXT** — Write shellcode (with appended INT3 if restore=true)
6. **PTRACE_SETREGS** — Set RIP to the shellcode address
7. **PTRACE_CONT** — Resume execution at the shellcode
8. **Wait for SIGTRAP** — Poll with timeout for the INT3 breakpoint
9. **PTRACE_POKETEXT** — Restore original code (if restore=true)
10. **PTRACE_SETREGS** — Restore original registers (if restore=true)
11. **PTRACE_DETACH** — Detach from the process

## Check Output

The `check` action reports:
- **ptrace_scope** — Yama LSM setting (0=classic, 1=restricted, 2=admin-only, 3=disabled)
- **Current UID/EUID** — Process identity
- **Capabilities** — CapInh, CapPrm, CapEff, CapBnd, CapAmb
- **Candidate Processes** — Same-UID processes available for injection (up to 20)

## OPSEC Considerations

- **ptrace_scope** controls who can attach:
  - `0` (classic): Any same-UID process can ptrace — injection works freely
  - `1` (restricted): Only parent can ptrace child — must be a child process of the agent
  - `2` (admin-only): Requires `CAP_SYS_PTRACE` capability
  - `3` (disabled): No ptrace allowed at all
- Root (EUID 0) bypasses ptrace_scope restrictions
- `check` action only reads from `/proc` — no subprocess execution
- `inject` action uses only ptrace syscalls — no external binary invocation
- Shellcode execution is in the context of the target process (PID, UID, capabilities)
- If `restore=true`, the target process resumes normal execution after injection — minimal forensic footprint
- If `restore=false`, the process is permanently modified — original code at the injection point is lost
- On failure at any step, cleanup is attempted (restore code + registers + detach)
- x86_64 architecture only (uses `PTRACE_GETREGS`/`PTRACE_SETREGS` with `PtraceRegs`)

## LD_PRELOAD Hijacking

The `ld-preload`, `ld-install`, and `ld-remove` actions implement T1574.006 (Dynamic Linker Hijacking):

```
# List current LD_PRELOAD settings from all sources
ptrace-inject -action ld-preload

# Install LD_PRELOAD persistence (auto-selects based on privilege)
ptrace-inject -action ld-install -libpath /tmp/evil.so

# Install to a specific target
ptrace-inject -action ld-install -libpath /tmp/evil.so -target ld.so.preload

# Remove LD_PRELOAD entry
ptrace-inject -action ld-remove -libpath /tmp/evil.so
```

- **Root**: Writes to `/etc/ld.so.preload` — affects all dynamically linked binaries system-wide
- **User**: Adds `export LD_PRELOAD=` to shell profile (`.bashrc`, `.zshrc`, etc.) — affects new shells
- Auto mode selects based on current UID

## MITRE ATT&CK Mapping

- **T1055.008** — Process Injection: Ptrace System Calls
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
