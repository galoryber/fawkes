+++
title = "jxa"
chapter = false
weight = 220
hidden = false
+++

## Summary

Execute JavaScript for Automation (JXA) scripts on macOS. JXA is the modern macOS scripting engine with Objective-C bridge access to Foundation, AppKit, Security, and other frameworks — making it a powerful post-exploitation scripting engine for macOS enumeration and automation.

{{% notice info %}}macOS Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| code | No* | | Inline JXA code to execute |
| file | No* | | Path to a .js file on the target to execute |
| timeout | No | 60 | Execution timeout in seconds |

*One of `code` or `file` must be specified, but not both.

## Usage

```
# Simple arithmetic
jxa -code '2 + 2'

# Get current username via ObjC bridge
jxa -code 'ObjC.import("Foundation"); $.NSUserName().js'

# List running applications
jxa -code 'Application("System Events").processes().name().join("\n")'

# Get home directory via Foundation
jxa -code 'ObjC.import("Foundation"); $.NSHomeDirectory().js'

# List files using Foundation NSFileManager
jxa -code 'ObjC.import("Foundation"); var fm = $.NSFileManager.defaultManager; var items = fm.contentsOfDirectoryAtPathError("/tmp", null); var result = []; for (var i = 0; i < items.count; i++) result.push(items.objectAtIndex(i).js); result.join("\n")'

# Execute script from file
jxa -file /tmp/recon.js

# With custom timeout (2 minutes)
jxa -code 'delay(5); "done"' -timeout 120
```

### Example Output

```
# jxa -code 'ObjC.import("Foundation"); $.NSUserName().js'
gary

# jxa -code '2 + 2'
4
```

## Common JXA Patterns

### Application Enumeration
```javascript
// List all running apps
Application("System Events").processes().name()

// Get app bundle info
Application("System Events").processes.whose({name: "Safari"})()[0].bundleIdentifier()
```

### File Operations via Foundation
```javascript
ObjC.import("Foundation")
var fm = $.NSFileManager.defaultManager
var items = fm.contentsOfDirectoryAtPathError("/Users", null)
```

### System Information
```javascript
ObjC.import("Foundation")
// Get hostname
$.NSHost.currentHost.localizedName.js

// Get OS version
$.NSProcessInfo.processInfo.operatingSystemVersionString.js
```

### Keychain Queries (Security Framework)
```javascript
ObjC.import("Security")
// Note: requires appropriate TCC permissions
```

## Operational Notes

- JXA executes via `osascript -l JavaScript` — this process will appear in process listings
- Some APIs (System Events, Accessibility) require TCC permissions; commands will fail gracefully with permission errors
- The ObjC bridge (`ObjC.import()`) provides access to most macOS frameworks without compilation
- Use inline `-code` for quick one-liners; use `-file` for complex multi-line scripts
- Timeout prevents indefinite execution — increase for long-running scripts

## MITRE ATT&CK Mapping

- **T1059.007** — Command and Scripting Interpreter: JavaScript
