+++
title = "jobkill"
chapter = false
weight = 100
hidden = false
+++

## Summary

Stop a running task by its task ID. Use `jobs` to list currently running tasks and their IDs.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| id | Yes | — | Task UUID to stop (from `jobs` output) |

## Usage

```
jobkill -id a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### Example Output

```
Stop signal sent to task a1b2c3d4-e5f6-7890-abcd-ef1234567890 (portscan)
```

## Notes

- The stop signal is cooperative — commands must check `DidStop()` to respond to it
- Commands with stop support: `download`, `upload`, `screenshot`, `procdump`
- Long-running network commands (portscan, socks, keylog) should also check the stop flag
- If a command doesn't check `DidStop()`, it will run to completion even after jobkill
