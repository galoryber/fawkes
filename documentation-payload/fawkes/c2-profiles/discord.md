+++
title = "Discord C2 Profile"
chapter = false
weight = 30
hidden = false
+++

## Summary

The Discord C2 profile uses a Discord bot and channel as a covert communication transport. The agent posts encrypted messages to a Discord channel via the REST API. A server-side Discord bot monitors the channel and relays messages to Mythic via gRPC push C2.

This profile is useful when HTTP/HTTPS egress is monitored or blocked, but Discord traffic (discord.com, gateway.discord.gg) is permitted.

## Architecture

```
Fawkes Agent ──HTTPS──→ Discord REST API ──→ Discord Channel
                                                    ↕
Mythic Server ←──gRPC──→ Discord C2 Server ←──Bot──→ Discord Channel
```

**Message flow:**

1. Agent encrypts a Mythic message and posts it to the Discord channel as a JSON-wrapped payload
2. The server-side Discord bot detects the new message and forwards it to Mythic via gRPC
3. Mythic processes the message and sends the response back through the gRPC stream
4. The bot posts the response to the Discord channel
5. The agent polls the channel and retrieves the response

## Build Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `discord_token` | String | Discord bot token for API authentication | _(required)_ |
| `bot_channel` | String | Discord channel ID for message exchange | _(required)_ |
| `callback_interval` | String | Seconds between tasking polls | `10` |
| `callback_jitter` | String | Jitter percentage (0-100) | `23` |
| `message_checks` | String | Max polling attempts per message exchange | `20` |
| `time_between_checks` | String | Seconds between poll attempts within an exchange | `5` |
| `AESPSK` | String | Pre-shared AES-256 encryption key | _(auto-generated)_ |
| `proxy_url` | String | Optional HTTP/SOCKS proxy for Discord API calls | _(empty)_ |

## Encryption

The Discord profile uses the same encryption scheme as the HTTP profile:

- **AES-256-CBC** with **HMAC-SHA256** for message integrity
- Message format: `UUID (36 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)`
- IV is randomly generated per message
- Messages are base64-encoded after encryption

Additionally, sensitive configuration (bot token, channel ID, encryption key) is encrypted in-memory using **AES-256-GCM** after agent initialization. This prevents credential extraction from process memory dumps.

## Push C2 and Task Delivery

The Discord C2 server uses Mythic's **push C2** mode (persistent gRPC stream). This means:

- Tasks may be pushed to the Discord channel asynchronously, outside the normal get_tasking cycle
- The agent implements several reliability mechanisms:
  - **Pre-poll sweep:** Before sending get_tasking, checks for any already-pushed tasks in the channel
  - **Collect-all polling:** Each poll cycle collects ALL matching messages (not just the first), because both get_tasking responses and pushed tasks share the same channel
  - **Catch-up polling:** After finding a match, performs 3 additional polls (5-second intervals) to capture rapidly queued tasks
  - **PostResponse retry:** Retries once on transient response failures

## Rate Limiting

The agent respects Discord API rate limits:

- Automatic retry with exponential backoff (up to 5 retries)
- Honors Discord's `Retry-After` response header
- The User-Agent is hardcoded to `DiscordBot (https://github.com, 1.0)` as required by the Discord API (custom User-Agents return HTTP 403)

## Message Size Handling

- Messages up to **1950 characters** are sent inline as JSON in Discord message content
- Larger messages are automatically uploaded as **file attachments** (Discord supports up to 25 MB per attachment)
- The agent handles both inline and attachment formats when reading responses

## Setup Prerequisites

### 1. Create a Discord Bot

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. Click **New Application** and give it a name
3. Go to **Bot** settings and click **Reset Token** to generate a bot token
4. Under **Privileged Gateway Intents**, enable **Message Content Intent**
5. Copy the bot token — you'll need it for both the build parameter and server config

### 2. Add the Bot to a Server

1. Go to **OAuth2** > **URL Generator**
2. Select scopes: `bot`
3. Select permissions: `Send Messages`, `Read Message History`, `Attach Files`, `Manage Messages`
4. Open the generated URL in a browser and add the bot to your server
5. Note the **channel ID** of the target channel (enable Developer Mode in Discord settings, then right-click the channel > Copy ID)

### 3. Configure the Server Container

The Discord C2 server container needs the same bot token and channel ID:

1. Edit the container's `config.json` (typically at `/Mythic/discord/c2_code/config.json`)
2. Set `botToken` and `channelID` to match the build parameters
3. Restart the container: `sudo ./mythic-cli restart discord`

{{% notice warning %}}
The `config.json` must be populated before the container starts. An empty config will prevent the bot from connecting to Discord.
{{% /notice %}}

## Operational Considerations

### OPSEC

- **Bot token is a critical asset.** Compromise of the bot token exposes the entire C2 channel. The agent encrypts the token in memory after initialization.
- **Channel visibility:** Use a private channel in a purpose-built Discord server. Public channels risk exposure.
- **Discord logging:** Discord retains message history. Messages are deleted after reading, but Discord may retain server-side logs.
- **Network signatures:** Traffic goes to `discord.com` and `cdn.discordapp.com` over HTTPS. This blends with normal Discord usage but may be flagged in environments where Discord is unusual.

### Last Checkin / "Streaming Now"

Because the Discord C2 server uses a persistent gRPC stream (push C2), Mythic's "Last Checkin" field shows **"Streaming Now"** while the stream is active. This is expected behavior:

- While the agent is active, checkin timing appears as "Streaming Now"
- After **~180 seconds of inactivity**, the server detects the agent has disconnected and updates the last checkin to a real timestamp
- This is inherent to push C2 mode and is not a bug

### Reliability

- Task delivery has ~1 callback_interval latency inherent to push C2 timing
- The catch-up polling mechanism significantly improves rapid-fire task delivery
- Rate limiting from Discord API may introduce additional latency during high-frequency operations

## MITRE ATT&CK Mapping

- **T1071.001** — Application Layer Protocol: Web Protocols (Discord REST API)
- **T1102.002** — Web Service: Bidirectional Communication (Discord as C2 channel)
- **T1573.001** — Encrypted Channel: Symmetric Cryptography (AES-256-CBC)
