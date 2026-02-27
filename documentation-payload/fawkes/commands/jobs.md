+++
title = "jobs"
chapter = false
weight = 100
hidden = false
+++

## Summary

List currently running tasks in the agent. Shows task ID, command name, and how long each task has been running. Use with `jobkill` to cancel long-running tasks.

## Arguments

None.

## Usage

```
jobs
```

### Example Output

```
Task ID                               Command               Running
------------------------------------------------------------------------
a1b2c3d4-e5f6-7890-abcd-ef1234567890  portscan              2m34s
f0e1d2c3-b4a5-6789-0abc-def123456789  socks                 15m22s
```

## Notes

- The `jobs` command itself does not appear in its own output
- All running tasks are tracked automatically by the agent
- Use `jobkill -id <task-uuid>` to stop a task
- Commands that check `DidStop()` (download, upload, screenshot, procdump) will exit gracefully when stopped
- Other commands will complete their current operation before the stop flag is checked
