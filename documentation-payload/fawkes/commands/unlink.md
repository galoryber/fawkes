+++
title = "unlink"
chapter = false
weight = 195
hidden = false
+++

## Summary

Disconnect a linked TCP P2P agent. This tears down the peer-to-peer connection and removes the agent from the link chain. The child agent will no longer receive tasking through this egress agent.

## Arguments

Argument | Required | Description
---------|----------|------------
connection_id | Yes | UUID of the linked agent to disconnect

## Usage

```
unlink -connection_id a1b2c3d4-5678-9abc-def0-123456789abc
```

## Example Output

```
Successfully unlinked agent a1b2c3d4
```

## MITRE ATT&CK Mapping

- **T1572** - Protocol Tunneling

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
