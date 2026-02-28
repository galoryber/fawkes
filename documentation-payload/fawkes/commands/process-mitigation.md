+++
title = "process-mitigation"
chapter = false
weight = 102
hidden = false
+++

## Summary

Query or set Windows process mitigation policies. These policies control security features like DEP, ASLR, Code Integrity Guard (CIG), Arbitrary Code Guard (ACG), and Control Flow Guard (CFG).

Setting CIG on the agent's process blocks unsigned DLL loading, which can prevent EDR agents from injecting monitoring DLLs. Setting ACG prohibits dynamic code generation. Setting child-block prevents the agent from spawning child processes (reducing forensic footprint).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | query | `query` to list all policies, `set` to enable a specific policy on the current process |
| pid | No | 0 (self) | Process ID to query (only used with `query` action). 0 = current process |
| policy | No | cig | Policy to enable (only used with `set` action) |

### Available Policies (for set action)

| Policy | Description |
|--------|-------------|
| `cig` | Code Integrity Guard — only load Microsoft-signed DLLs (blocks unsigned EDR DLLs) |
| `acg` | Arbitrary Code Guard — prohibit dynamic code generation |
| `child-block` | Block child process creation |
| `dep` | Data Execution Prevention — permanently enable DEP |
| `cfg` | Control Flow Guard — enable CFG |
| `ext-disable` | Disable extension points (AppInit DLLs, etc.) |
| `image-restrict` | Block remote images, low-label images; prefer System32 |
| `font-disable` | Block non-system font loading |

## Usage

```
process-mitigation
process-mitigation -action query
process-mitigation -action query -pid 1234
process-mitigation -action set -policy cig
process-mitigation -action set -policy acg
process-mitigation -action set -policy child-block
```

### Example Output (query)

```
Process Mitigation Policies (self):
==================================================
DEP (Data Execution Prevention):
  Enabled:            true
  ATL Thunk Emulation: false
  Permanent:          true
ASLR (Address Space Layout Randomization):
  Bottom-Up:          true
  Force Relocate:     false
  High Entropy:       true
  Disallow Stripped:  false
ACG (Arbitrary Code Guard):
  Prohibit Dynamic Code: false
  Allow Thread Opt-Out:  false
  Allow Remote Downgrade: false
CFG (Control Flow Guard):
  Enabled:             false
  Export Suppression:  false
  Strict Mode:         false
CIG (Code Integrity Guard):
  Microsoft Signed Only: false
  Store Signed Only:     false
  Mitigation Opt-In:     false
Child Process:
  No Child Process Creation: false
```

### Example Output (set cig)

```
Successfully set: CIG (Code Integrity Guard) — Microsoft-signed DLLs only
```

## Opsec Considerations

- **CIG** is the most impactful defensive policy — it blocks unsigned DLLs from loading into the agent process, which prevents most EDR agents from injecting their monitoring DLLs
- Setting CIG may prevent loading DLLs required by other commands (e.g., BOF execution, reflective loading)
- **ACG** prevents dynamic code generation — this can break shellcode execution and .NET CLR hosting
- **child-block** prevents the agent from spawning child processes — commands like `run`, `shell`, and `spawn` will fail
- These policies are **one-way** — once set, they cannot be disabled for the current process
- Use `query` first to understand the current state before making changes

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1480 | Execution Guardrails |
