# Ctrl-C Handler Reversing Guide

## Objective

Find the `HandlerList` global variable and `CTRL_HANDLER` structure in kernelbase.dll to enable handler chain injection.

## Method 1: WinDbg Analysis

### Setup
```
1. Open WinDbg
2. Attach to any console process (cmd.exe works)
3. Load symbols: .symfix; .reload
```

### Find HandlerList

```windbg
# Search for SetConsoleCtrlHandler
x kernelbase!*SetConsoleCtrlHandler*

# Disassemble it
uf kernelbase!SetConsoleCtrlHandler

# Look for references to global variables
# The handler list head will be accessed early in the function
# Look for patterns like:
#   lea rcx, [kernelbase!SomeGlobalName]
#   mov rax, [kernelbase!HandlerList]
```

### Expected Findings

We're looking for:
1. **HandlerList** - pointer to first handler entry (or LIST_ENTRY head)
2. **HandlerListLock** - critical section protecting the list (if any)
3. **Structure layout** of each handler entry

### Dump the Structure

Once you find the list head:
```windbg
# If it's a simple linked list:
dps kernelbase!HandlerList L2

# If it's a LIST_ENTRY:
dt ntdll!_LIST_ENTRY poi(kernelbase!HandlerList)

# Follow the chain
!list -x "dps @$extret L4" poi(kernelbase!HandlerList)
```

## Method 2: Static Analysis (Ghidra/IDA)

### Steps
1. Open `C:\Windows\System32\kernelbase.dll` in Ghidra/IDA
2. Find `SetConsoleCtrlHandler` export
3. Analyze the function - look for:
   - Global variable references (the handler list)
   - Structure allocations (handler entry size)
   - Linked list operations (Next pointer manipulation)

### Key Patterns to Look For

```c
// Adding a handler typically looks like:
NewEntry = HeapAlloc(sizeof(CTRL_HANDLER_ENTRY));
NewEntry->Handler = HandlerRoutine;
NewEntry->Next = HandlerList;
HandlerList = NewEntry;

// Or with LIST_ENTRY:
InsertHeadList(&HandlerList, &NewEntry->ListEntry);
```

## Method 3: Runtime Analysis

### PowerShell Script to Find Handler List
```powershell
# This script sets a handler and watches memory to find the list
# Run in a PowerShell console

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ConsoleHandler {
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);

    public delegate bool HandlerRoutine(uint dwCtrlType);

    public static bool Handler(uint type) {
        Console.WriteLine("Handler called: " + type);
        return false;
    }
}
"@

# Get kernelbase base address
$proc = Get-Process -Id $PID
$kernelbase = $proc.Modules | Where-Object { $_.ModuleName -eq "kernelbase.dll" }
Write-Host "kernelbase.dll base: 0x$($kernelbase.BaseAddress.ToString('X'))"

# Register handler
$handler = [ConsoleHandler+HandlerRoutine]{ param($t) Write-Host "Got $t"; $false }
[ConsoleHandler]::SetConsoleCtrlHandler($handler, $true)

Write-Host "Handler registered. Use debugger to find HandlerList."
Write-Host "Process ID: $PID"
Read-Host "Press Enter to exit"
```

## Information Needed

After reversing, document:

### 1. HandlerList Offset
```
kernelbase.dll version: 10.0.xxxxx
HandlerList RVA: 0x????????
```

### 2. Structure Layout
```c
typedef struct _CTRL_HANDLER_ENTRY {
    // Document exact layout
    /* +0x00 */ ???
    /* +0x08 */ ???
} CTRL_HANDLER_ENTRY;
```

### 3. Locking Mechanism
- Is there a critical section?
- Name and offset of lock?

### 4. Handler Dispatch Function
- Name of function that walks the list (likely `CtrlRoutine` or similar)
- How does it iterate?

## Windows Version Considerations

The structure/offsets may differ between:
- Windows 10 (various builds)
- Windows 11
- Server editions

We may need version-specific offsets or pattern scanning.

## Pattern Scanning Alternative

If offsets vary too much, we can pattern scan for SetConsoleCtrlHandler and extract the HandlerList reference dynamically:

```
Pattern: 48 8D 0D ?? ?? ?? ?? (LEA RCX, [rip+offset])
```

Near the beginning of SetConsoleCtrlHandler, look for LEA instructions referencing globals.
