# Novel Process Injection Research

**Focus:** Non-callback injection techniques for Windows 11 25H2

**Background:** Previous research (see `opus-injection-research.md`) investigated callback-based injection and found:
- **6 of 7 callback mechanisms** are CFG protected (86% failure rate)
- Only **console control handlers** (Variant 1) remain unprotected
- Microsoft has systematically retrofitted CFG to all modern callback mechanisms

**New Goal:** Explore injection techniques that do NOT rely on callback hijacking. Find completely novel, undocumented methods to inject and execute shellcode in remote processes.

---

## Brainstormed Approach Categories

### 1. Direct Execution Manipulation
- Thread context hijacking
- Return address manipulation on stack
- Hardware debug register abuse
- Exception handler chains (non-VEH)

### 2. Memory-Only Execution
- Instruction pointer hijacking
- Page fault handler exploitation
- Timer/APC queue manipulation

### 3. Windows Feature Abuse
- Transaction Manager callbacks
- Application compatibility shims
- WSL boundary exploitation
- WMI event consumers
- COM/DCOM manipulation
- Scheduled task injection

### 4. Process/Thread Primitives
- Process hollowing variations
- Thread pool hijacking (non-callback)
- Fiber manipulation
- Module loading/unloading hooks

### 5. Kernel Boundary Exploitation
- Syscall hooking/redirection
- SSDT manipulation from user mode
- Kernel transition hijacking

### 6. Obscure/Legacy Subsystems
- Console architecture (deeper than Variant 1)
- Vestigial code paths Microsoft forgot

### 7. Return-Oriented Programming
- Pure ROP injection (no shellcode)
- JOP (Jump-Oriented Programming)

### 8. Race Conditions
- TOCTOU exploitation
- Thread interleaving attacks

---

## High-Priority Candidates

Based on novelty, feasibility, and likelihood of success:

### Candidate A: Console Architecture Deep Dive

**Rationale:** Variant 1 proved console subsystem has CFG gaps. There may be other unprotected mechanisms.

**Targets to investigate:**
- ConDrv.sys kernel driver
- ConhostV2.dll internals
- Console I/O completion mechanisms
- Console buffer manipulation
- Console mode flags exploitation

### Candidate B: Hardware Debug Register Hijacking

**Rationale:** Lesser-known than software techniques. Uses CPU hardware features.

**Approach:**
- Set hardware breakpoint (DR0-DR3) on frequently-executed function
- When breakpoint hits, exception handler redirects to shellcode
- Or: Modify debug registers to cause execution trap

**Research questions:**
- Can we remotely set debug registers in target process?
- Is debug exception dispatch CFG protected?
- How to avoid debugger detection?

### Candidate C: Thread Context Hijacking (Modern Variations)

**Classic technique:** Suspend thread, modify RIP to shellcode, resume

**Research angle:** Find novel variations or bypasses for modern mitigations:
- Can we hijack thread context without `SuspendThread`?
- Inline context modification during natural thread suspension?
- Combined with other techniques for stealthier approach?

### Candidate D: Pure ROP/JOP Injection

**Rationale:** No shellcode = different detection profile. Highly novel if unexplored.

**Approach:**
- Build ROP chain from existing DLL gadgets
- Manipulate target thread's stack to execute chain
- Achieve arbitrary code execution without injecting code

**Research questions:**
- Has ROP-only process injection been documented?
- Feasibility of building reliable cross-process ROP chains?
- Gadget availability in common Windows DLLs?

---

## Investigation Methodology

For each candidate:

1. **Literature review** - Check if documented/well-known
2. **CFG status check** - If callback-based, verify CFG protection
3. **Feasibility assessment** - Can we implement it?
4. **Prototype** - If viable, build PoC
5. **Document** - Record findings

---

## Decision Point

**What should we investigate first?**

Options:
1. Start with **Candidate A (Console Deep Dive)** - Build on Variant 1 success
2. Start with **Candidate B (Debug Registers)** - Completely different approach
3. Start with **Candidate C (Thread Context Hijacking)** - Classic with modern variations
4. Start with **Candidate D (Pure ROP)** - Most novel, highest complexity
5. Implement **CFG bypass** to unlock all blocked callback techniques from previous research

Your input?

---

## Research Log

*(Investigations will be documented below as we proceed)*

