+++
title = "email"
chapter = false
weight = 212
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Access Outlook mailbox via COM API. Uses `Outlook.Application` COM object to connect to the MAPI namespace and interact with mail folders. Supports counting messages, keyword searching (subject and body), reading individual messages with full headers and attachment info, and listing all available folders.

**Note:** Requires Outlook to be installed on the target. Uses indexed access to avoid COM collection iteration hangs. Messages are sorted by received time (most recent first).

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | count | `count`, `search`, `read`, or `folders` |
| folder | string | No | Inbox | Mail folder name. Standard: Inbox, Sent, Drafts, Deleted, Outbox, Junk. Custom folder names also supported. |
| query | string | No | - | Search keyword (matches subject and body). Required for `search` action. |
| index | number | No | 1 | Message index to read (1-based, most recent first). Required for `read` action. |
| count | number | No | 10 | Maximum number of results to return for search. |
| headers | boolean | No | false | If true, show message headers only (skip body) when reading. |

## Usage

### Count Messages

Count messages in the inbox:
```
email -action count
```

Count messages in a specific folder:
```
email -action count -folder "Sent"
```

### Search Messages

Search for messages containing a keyword:
```
email -action search -query "password reset"
```

Search in a specific folder with more results:
```
email -action search -query "invoice" -folder "Inbox" -count 25
```

### Read a Message

Read the most recent message:
```
email -action read -index 1
```

Read headers only (no body):
```
email -action read -index 3 -headers true
```

### List Folders

List all available Outlook folders with message counts:
```
email -action folders
```

### Example Output

**Count:**
```
Inbox: 47 messages
```

**Search:**
```
Search 'password': 3 matches

[1] 2026-03-10 09:15:22 | John Smith | Password Reset Request
[2] 2026-03-08 14:30:05 | IT Support | Your password expires in 3 days
[3] 2026-03-05 11:22:41 | Security Team | Password Policy Update
```

**Read:**
```
Subject: Password Reset Request
From: John Smith <john.smith@company.com>
To: user@company.com
Received: 2026-03-10 09:15:22
Attachments: 1
  [1] instructions.pdf (45632 bytes)

--- Body ---
Hi, please reset your password using the attached instructions...
```

## MITRE ATT&CK Mapping

- T1114.001 -- Email Collection: Local Email Collection
