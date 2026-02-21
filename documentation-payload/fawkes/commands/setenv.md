+++
title = "setenv"
chapter = false
weight = 131
hidden = false
+++

## Summary

Set or unset environment variables in the agent process. Changes persist for the lifetime of the agent and affect subsequent commands (e.g., `run`, `powershell`).

## Arguments

#### action (required)
- `set` — Set an environment variable to the specified value
- `unset` — Remove an environment variable

#### name (required)
The environment variable name (e.g., `PATH`, `HTTP_PROXY`).

#### value (optional)
The value to assign. Only used with the `set` action. Can be empty to set a variable with no value.

## Usage
```
setenv -action set -name HTTP_PROXY -value http://127.0.0.1:8080
setenv -action set -name TEMP -value C:\Users\Public\Temp
setenv -action unset -name HTTP_PROXY
```

Use `env` to verify changes:
```
env HTTP_PROXY
```

## MITRE ATT&CK Mapping

- T1480 — Execution Guardrails (environment variable manipulation)
