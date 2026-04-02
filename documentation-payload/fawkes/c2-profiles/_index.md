+++
title = "C2 Profiles"
chapter = true
weight = 20
pre = "<b>3. </b>"
+++

Fawkes supports multiple C2 communication profiles. Each profile defines how the agent communicates with the Mythic server.

## Available Profiles

- [HTTP](/agents/fawkes/c2-profiles/http/) — Standard HTTP/HTTPS polling (default egress)
- [HTTPx](/agents/fawkes/c2-profiles/httpx/) — Malleable HTTP/HTTPS with configurable transforms
- [TCP P2P](/agents/fawkes/c2-profiles/tcp/) — Peer-to-peer agent linking for internal pivoting
- [Discord](/agents/fawkes/c2-profiles/discord/) — Covert C2 via Discord bot and channel
