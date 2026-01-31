# Opus Injection Research

Novel process injection techniques developed for the Fawkes agent, focusing on unexplored callback mechanisms in Windows.

## Overview

The "Opus Injection" family of techniques explores Windows callback mechanisms that haven't been weaponized in common tooling. The goal is to find function pointer structures in target processes that can be manipulated to achieve code execution through legitimate Windows API triggers.

---

## Variant 1: Ctrl-C Handler Chain Injection

### Concept

Windows console applications can register Ctrl+C/Ctrl+Break handlers via `SetConsoleCtrlHandler`. These handlers are stored in a linked list within `kernelbase.dll`. When a console control event occurs, Windows walks this list and calls each handler.

**Key Insight:** The handler list is just memory in the target process. If we can:
1. Write shellcode to the target process
2. Inject a fake handler node into the list
3. Trigger a console control event

...then Windows itself will execute our shellcode as part of its normal handler dispatch.

### Target Scope

- **Console processes only** (cmd.exe, powershell.exe, services with console, CLI tools)
- This is actually a large attack surface - many backend services and tools are console applications

### Technical Details

#### Handler Structure (CONFIRMED via WinDbg reversing)

The handler list is NOT a linked list - it's a **heap-allocated array** of encoded function pointers!

```c
// Global variables in kernelbase.dll (confirmed)
PHANDLER_ROUTINE* HandlerList;          // RVA: 0x399490 - Pointer to heap array
DWORD HandlerListLength;                 // RVA: 0x39CBB0 - Current handler count
DWORD AllocatedHandlerListLength;        // RVA: 0x39CBB4 - Array capacity
PHANDLER_ROUTINE SingleHandler;          // RVA: 0x39CBA8 - Optimization for single handler
CRITICAL_SECTION ConsoleStateLock;       // RVA: 0x39CC00 - Lock protecting the list

// Handler routine signature
typedef BOOL (WINAPI *PHANDLER_ROUTINE)(DWORD dwCtrlType);

// Array structure:
// HandlerList[0] = encoded_handler_0
// HandlerList[1] = encoded_handler_1
// ...
// HandlerList[HandlerListLength-1] = encoded_handler_n
```

**CRITICAL:** Handlers are encoded with `RtlEncodePointer` (XOR with PEB cookie at offset 0x78).
We must encode our shellcode address or it will fail when Windows tries to decode it!

#### Pointer Encoding

```c
// RtlEncodePointer implementation (simplified)
PVOID RtlEncodePointer(PVOID Pointer) {
    ULONG_PTR Cookie = *(ULONG_PTR*)(NtCurrentPeb() + 0x78);
    return (PVOID)((ULONG_PTR)Pointer ^ Cookie);
}

// To inject, we must:
// 1. Read target's PEB address (NtQueryInformationProcess)
// 2. Read cookie from PEB+0x78
// 3. XOR our shellcode address with cookie
// 4. Write encoded address to handler array
```

#### Attack Flow (IMPLEMENTED)

```
1. OpenProcess(target_pid) with VM_READ, VM_WRITE, VM_OPERATION, QUERY_INFORMATION
2. Find kernelbase.dll base in target process (EnumProcessModulesEx)
3. Calculate addresses:
   - HandlerList pointer: kernelbase + 0x399490
   - HandlerListLength: kernelbase + 0x39CBB0
   - AllocatedHandlerListLength: kernelbase + 0x39CBB4
4. Read handler array pointer, current count, and capacity
5. Verify capacity > count (room for new handler)
6. Get target PEB address (NtQueryInformationProcess)
7. Read pointer encoding cookie from PEB+0x78
8. VirtualAllocEx - allocate RWX memory for shellcode
9. WriteProcessMemory - write shellcode
10. Encode shellcode address: encoded = shellcode_addr XOR cookie
11. Write encoded pointer to HandlerList[HandlerListLength]
12. Increment HandlerListLength
13. AttachConsole(target_pid)
14. GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)
15. Windows decodes and calls our shellcode as a handler!
```

#### Key APIs

| API | Purpose |
|-----|---------|
| `SetConsoleCtrlHandler` | Legitimate API - reverse to understand structure |
| `AttachConsole` | Attach to target's console session |
| `GenerateConsoleCtrlEvent` | Trigger the Ctrl+C event |
| `CtrlRoutine` (internal) | Dispatcher that walks handler list |

### Research Tasks

- [x] Disassemble `kernelbase!SetConsoleCtrlHandler` to find HandlerList offset
- [x] Verify CTRL_HANDLER_ENTRY structure layout (it's an array, not linked list!)
- [x] Check for critical section locking requirements (ConsoleStateLock exists but we bypass it)
- [ ] Test AttachConsole + GenerateConsoleCtrlEvent cross-process
- [ ] Determine if handler must return TRUE/FALSE (shellcode should handle this)
- [ ] Check Windows version differences (Win10 vs Win11) - RVAs may differ!

### Detection Surface

| Action | Telemetry |
|--------|-----------|
| WriteProcessMemory | Standard - unavoidable |
| VirtualAllocEx | Standard - unavoidable |
| AttachConsole | Uncommon - low monitoring |
| GenerateConsoleCtrlEvent | Uncommon - low monitoring |

**Advantage:** No CreateRemoteThread, no APC, no thread pool manipulation. Different API surface than typical injection.

### Limitations

- Console processes only
- Target must have a console (not detached)
- GenerateConsoleCtrlEvent affects process groups - need careful targeting

---

## Variant 2: WNF (Windows Notification Facility) Callback Injection

### Concept

WNF is an obscure publish/subscribe notification system in Windows used internally by OS components. Subscribers register callbacks that fire when state changes occur.

### Status: Research Phase

### Key Components
- `NtCreateWnfStateName` - Create a notification state
- `RtlSubscribeWnfStateChangeNotification` - Register callback
- `NtUpdateWnfStateData` - Publish data (triggers callbacks)
- Subscription list stored in ntdll internal structures

### Research Tasks
- [ ] Reverse WNF subscription structures in ntdll
- [ ] Understand WNF state name format
- [ ] Test local WNF callback registration
- [ ] Explore remote subscription injection feasibility

---

## Variant 3: FLS (Fiber Local Storage) Callback Injection

### Concept

Fiber Local Storage allows associating data with fibers, with optional cleanup callbacks when slots are freed.

### Status: Research Phase

### Key Components
- `FlsAlloc` - Allocate FLS slot with optional callback
- `FlsFree` - Free slot, triggers callback
- `FlsCallback` array in ntdll

### Research Tasks
- [ ] Locate FlsCallback array in ntdll
- [ ] Understand FLS_INFO_CHUNK structure
- [ ] Determine how to trigger FlsFree remotely

---

## Future Variant Ideas

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

## References

- Windows Internals, 7th Edition
- ReactOS source code (for structure hints)
- Various security research papers on callback abuse
