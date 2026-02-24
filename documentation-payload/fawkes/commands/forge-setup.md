+++
title = "Forge Command Augmentation"
chapter = false
weight = 200
hidden = false
+++

## Summary

Fawkes supports [Mythic Forge](https://github.com/MythicAgents/forge) command augmentation, which dynamically extends the agent's capabilities with external tool collections like **SharpCollection** (.NET tools) and **Sliver Armory** (BOF/COFF tools).

When Forge is installed, additional commands appear in the Mythic UI for your Fawkes callbacks, giving you access to hundreds of community tools without modifying the agent.

## How It Works

1. **Forge container** runs alongside Mythic and provides tool definitions (SharpCollection, Sliver Armory)
2. **Mythic UI** merges Forge's augmented commands with Fawkes's base commands
3. When you run a Forge command, Mythic sends the parameters to Fawkes with Forge-specific formatting
4. Fawkes detects the Forge parameter group and handles conversion transparently

Forge tools execute through Fawkes's existing capabilities:
- **.NET assemblies** (SharpCollection) → `inline-assembly` command
- **BOF/COFF files** (Sliver Armory) → `inline-execute` command

## Installation

### Step 1: Install Forge Container

On your Mythic server:

```bash
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/MythicAgents/forge
```

### Step 2: Verify Forge Is Running

```bash
sudo ./mythic-cli status
```

Look for the `mythic_forge` container in the output. It should show as running.

### Step 3: Restart Fawkes (if needed)

If Fawkes was already installed before Forge, restart the containers:

```bash
sudo ./mythic-cli restart fawkes
```

### Step 4: Generate a Fawkes Payload

Generate a Fawkes payload as usual through the Mythic UI. No special build parameters are needed for Forge support — it's built in.

### Step 5: Use Augmented Commands

Once a Fawkes callback is active:

1. Open the callback's task interface in Mythic UI
2. Look for augmented commands from Forge (they appear alongside Fawkes's base commands)
3. Select a tool from SharpCollection or Sliver Armory
4. Fill in the parameters and execute

## Supported Tool Collections

### SharpCollection (.NET Assemblies)

Tools from [Flangvik's SharpCollection](https://github.com/Flangvik/SharpCollection) execute through `inline-assembly`. Examples:

- **Seatbelt** — Host security checks and enumeration
- **SharpUp** — Privilege escalation checks
- **Rubeus** — Kerberos abuse toolkit
- **Certify** — AD Certificate Services enumeration
- **SharpHound** — BloodHound data collection
- **SharpDPAPI** — DPAPI credential extraction

{{% notice tip %}}
Run `start-clr` before using .NET tools to set up AMSI bypass. Example workflow:
```
start-clr
autopatch amsi AmsiScanBuffer 300
(then run SharpCollection tool via Forge)
```
{{% /notice %}}

### Sliver Armory (BOF/COFF Files)

Tools from the Sliver Armory execute through `inline-execute`. Examples:

- **SA-whoami** — Token and privilege enumeration
- **SA-adcs-enum** — AD Certificate Services enumeration
- **SA-ldapsearch** — LDAP queries
- **SA-nanodump** — MiniDump alternative

## Parameter Handling

Forge sends parameters in its own format, which Fawkes converts automatically:

### BOF Arguments (TypedArray Format)

Forge sends BOF arguments as a TypedArray:
```
[["z", "hostname"], ["i", "80"], ["b", "AQIDBA=="]]
```

Fawkes converts this to its internal format:
```
["zhostname", "i80", "bAQIDBA=="]
```

**Supported types:**

Type | Aliases | Description
-----|---------|------------
`z` | `string` | ASCII string
`Z` | `wchar` | Wide (Unicode) string
`i` | `int`, `int32` | 32-bit integer
`s` | `short`, `int16` | 16-bit integer
`b` | `binary`, `base64` | Binary data (base64-encoded)

### .NET Assembly Arguments

Forge sends assembly arguments as a plain string, which Fawkes passes through directly. No conversion needed.

## Troubleshooting

### Forge commands not appearing in UI

- Verify `mythic_forge` container is running: `sudo ./mythic-cli status`
- Restart Mythic: `sudo ./mythic-cli restart`
- Check Forge container logs: `sudo ./mythic-cli logs forge`

### .NET assembly fails to load

- Ensure CLR is initialized: run `start-clr` first
- If AMSI blocks the assembly: use `autopatch amsi AmsiScanBuffer 300` before loading
- Check that the assembly targets .NET Framework 4.x (not .NET Core/5+)

### BOF execution crashes

- Verify the BOF is compiled for x64 (Fawkes only runs 64-bit BOFs)
- Check that argument types match what the BOF expects
- Some BOFs require specific argument counts — check the tool's documentation

## For Developers

To add Forge support to a new command:

1. **Add a "Forge" parameter group** in your agentfunctions definition with Forge-specific parameters (e.g., `bof_file` instead of `filename`)
2. **Detect Forge calls** by checking for the Forge parameter:
   ```go
   forgeFileID, err := taskData.Args.GetStringArg("bof_file")
   isForge := err == nil && forgeFileID != ""
   ```
3. **Convert Forge parameters** to your command's native format
4. **Fall back** to non-Forge parameter handling for direct usage

See `agentfunctions/inlineexecute.go` and `agentfunctions/inlineassembly.go` for reference implementations.
