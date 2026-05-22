package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type sharePermResult struct {
	Share  string `json:"share"`
	Read   bool   `json:"read"`
	Write  bool   `json:"write"`
	Error  string `json:"error,omitempty"`
	Files  int    `json:"files,omitempty"`
	Remark string `json:"remark,omitempty"`
}

type spiderEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Modified string `json:"modified"`
}

type searchMatch struct {
	Share    string `json:"share"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	Pattern  string `json:"pattern"`
}

var defaultSensitivePatterns = []string{
	"*.kdbx", "*.kdb",
	"*.pfx", "*.p12", "*.pem", "*.key", "*.cer",
	"web.config", "appsettings.json", "appsettings.*.json",
	"unattend.xml", "unattend.answer",
	"*.vmdk", "*.vhd", "*.vhdx",
	"*.bak", "*.old",
	"passwords.*", "credentials.*", "secrets.*",
	"Groups.xml",
	"*.rdg", "*.rdp",
	"id_rsa", "id_ed25519", "id_ecdsa",
	"*.ppk",
	"*.mdb", "*.accdb",
	"NTDS.dit", "SAM", "SYSTEM", "SECURITY",
	"*.dmp",
	"*.sql",
	"*.conf", "*.ini",
	"*.env",
	"KeePass.config.xml",
	"ConsoleHost_history.txt",
}

// smbSharePerms enumerates all shares on a host and tests effective access (read/write).
func smbSharePerms(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	shares, err := sc.session.ListSharenames()
	sc.clearDeadline()
	if err != nil {
		return errorf("Error listing shares: %v", err)
	}

	var results []sharePermResult
	for _, shareName := range shares {
		r := testShareAccess(sc, shareName)
		results = append(results, r)
	}

	data, err := json.Marshal(results)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}
	return successResult(string(data))
}

func testShareAccess(sc *smbConn, shareName string) sharePermResult {
	r := sharePermResult{Share: shareName}

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(shareName)
	sc.clearDeadline()
	if err != nil {
		r.Error = fmt.Sprintf("mount failed: %v", err)
		return r
	}
	defer func() { _ = share.Umount() }()

	// Test read access
	sc.setDeadline(smbOperationTimeout)
	entries, err := share.ReadDir(".")
	sc.clearDeadline()
	if err != nil {
		r.Error = fmt.Sprintf("read denied: %v", err)
		return r
	}
	r.Read = true
	r.Files = len(entries)

	// Classify share type
	r.Remark = classifyShare(shareName, entries)

	// Test write access with a temp file
	testFile := fmt.Sprintf(".fawkes_perm_test_%d", time.Now().UnixNano()%100000)
	sc.setDeadline(smbOperationTimeout)
	f, err := share.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	sc.clearDeadline()
	if err == nil {
		_ = f.Close()
		sc.setDeadline(smbOperationTimeout)
		_ = share.Remove(testFile)
		sc.clearDeadline()
		r.Write = true
	}

	return r
}

// classifyShare provides a human-readable remark about a share.
func classifyShare(name string, entries []os.FileInfo) string {
	upper := strings.ToUpper(name)
	switch upper {
	case "C$", "D$", "E$":
		return "Administrative drive share"
	case "ADMIN$":
		return "Windows system directory"
	case "IPC$":
		return "IPC (inter-process communication)"
	case "SYSVOL":
		return "Active Directory SYSVOL"
	case "NETLOGON":
		return "Active Directory NETLOGON"
	case "PRINT$":
		return "Printer drivers"
	}
	if len(entries) == 0 {
		return "Empty share"
	}
	return fmt.Sprintf("%d entries", len(entries))
}

// smbShareSpider recursively lists files on a share.
func smbShareSpider(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	depth := args.Depth
	if depth <= 0 {
		depth = 3
	}
	maxResults := args.MaxResults
	if maxResults <= 0 {
		maxResults = 500
	}

	extFilter := parseExtensions(args.Extensions)

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	startPath := args.Path
	if startPath == "" {
		startPath = "."
	}
	startPath = strings.TrimLeft(startPath, "\\/")
	if startPath == "" {
		startPath = "."
	}

	var results []spiderEntry
	spiderWalk(sc, share, startPath, 0, depth, extFilter, maxResults, &results)

	type spiderOutput struct {
		Host    string        `json:"host"`
		Share   string        `json:"share"`
		Path    string        `json:"path"`
		Depth   int           `json:"depth"`
		Count   int           `json:"count"`
		Entries []spiderEntry `json:"entries"`
	}

	out := spiderOutput{
		Host:    args.Host,
		Share:   args.Share,
		Path:    startPath,
		Depth:   depth,
		Count:   len(results),
		Entries: results,
	}

	data, err := json.Marshal(out)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}
	return successResult(string(data))
}

// spiderWalk recursively reads directories up to maxDepth.
func spiderWalk(sc *smbConn, share interface{ ReadDir(string) ([]os.FileInfo, error) },
	dir string, currentDepth, maxDepth int, extFilter map[string]bool, maxResults int, results *[]spiderEntry) {

	if currentDepth >= maxDepth || len(*results) >= maxResults {
		return
	}

	sc.setDeadline(smbOperationTimeout)
	entries, err := share.ReadDir(dir)
	sc.clearDeadline()
	if err != nil {
		return
	}

	for _, entry := range entries {
		if len(*results) >= maxResults {
			return
		}

		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}

		fullPath := name
		if dir != "." && dir != "" {
			fullPath = dir + "\\" + name
		}

		if entry.IsDir() {
			*results = append(*results, spiderEntry{
				Path:     fullPath,
				IsDir:    true,
				Modified: entry.ModTime().Format("2006-01-02 15:04:05"),
			})
			spiderWalk(sc, share, fullPath, currentDepth+1, maxDepth, extFilter, maxResults, results)
		} else {
			if len(extFilter) > 0 {
				ext := strings.ToLower(filepath.Ext(name))
				if !extFilter[ext] {
					continue
				}
			}
			*results = append(*results, spiderEntry{
				Path:     fullPath,
				Size:     entry.Size(),
				Modified: entry.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
	}
}

// smbShareSearch searches for sensitive files across one or all shares.
func smbShareSearch(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	depth := args.Depth
	if depth <= 0 {
		depth = 3
	}
	maxResults := args.MaxResults
	if maxResults <= 0 {
		maxResults = 200
	}

	patterns := defaultSensitivePatterns
	if args.Patterns != "" {
		patterns = splitAndTrim(args.Patterns)
	}

	// Determine which shares to search
	var sharesToSearch []string
	if args.Share != "" {
		sharesToSearch = []string{args.Share}
	} else {
		sc.setDeadline(smbOperationTimeout)
		shares, err := sc.session.ListSharenames()
		sc.clearDeadline()
		if err != nil {
			return errorf("Error listing shares: %v", err)
		}
		sharesToSearch = shares
	}

	var matches []searchMatch
	for _, shareName := range sharesToSearch {
		if len(matches) >= maxResults {
			break
		}
		searchShare(sc, shareName, args.Path, 0, depth, patterns, maxResults, &matches)
	}

	type searchOutput struct {
		Host     string        `json:"host"`
		Patterns []string      `json:"patterns"`
		Depth    int           `json:"depth"`
		Count    int           `json:"count"`
		Matches  []searchMatch `json:"matches"`
	}

	out := searchOutput{
		Host:     args.Host,
		Patterns: patterns,
		Depth:    depth,
		Count:    len(matches),
		Matches:  matches,
	}

	data, err := json.Marshal(out)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}
	return successResult(string(data))
}

func searchShare(sc *smbConn, shareName, startPath string, currentDepth, maxDepth int,
	patterns []string, maxResults int, matches *[]searchMatch) {

	if currentDepth >= maxDepth || len(*matches) >= maxResults {
		return
	}

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(shareName)
	sc.clearDeadline()
	if err != nil {
		return
	}
	defer func() { _ = share.Umount() }()

	dir := startPath
	if dir == "" {
		dir = "."
	}
	dir = strings.TrimLeft(dir, "\\/")
	if dir == "" {
		dir = "."
	}

	searchDir(sc, share, shareName, dir, currentDepth, maxDepth, patterns, maxResults, matches)
}

func searchDir(sc *smbConn, share interface{ ReadDir(string) ([]os.FileInfo, error) },
	shareName, dir string, currentDepth, maxDepth int, patterns []string, maxResults int, matches *[]searchMatch) {

	if currentDepth >= maxDepth || len(*matches) >= maxResults {
		return
	}

	sc.setDeadline(smbOperationTimeout)
	entries, err := share.ReadDir(dir)
	sc.clearDeadline()
	if err != nil {
		return
	}

	for _, entry := range entries {
		if len(*matches) >= maxResults {
			return
		}

		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}

		fullPath := name
		if dir != "." && dir != "" {
			fullPath = dir + "\\" + name
		}

		if entry.IsDir() {
			searchDir(sc, share, shareName, fullPath, currentDepth+1, maxDepth, patterns, maxResults, matches)
		} else {
			if matched, pat := matchesAnyPattern(name, patterns); matched {
				*matches = append(*matches, searchMatch{
					Share:    shareName,
					Path:     fullPath,
					Size:     entry.Size(),
					Modified: entry.ModTime().Format("2006-01-02 15:04:05"),
					Pattern:  pat,
				})
			}
		}
	}
}

// matchesAnyPattern checks if a filename matches any of the given glob patterns.
func matchesAnyPattern(name string, patterns []string) (bool, string) {
	nameLower := strings.ToLower(name)
	for _, pat := range patterns {
		patLower := strings.ToLower(pat)
		if matched, _ := filepath.Match(patLower, nameLower); matched {
			return true, pat
		}
	}
	return false, ""
}

// parseExtensions splits a comma-separated extension string into a lookup map.
func parseExtensions(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, ext := range splitAndTrim(s) {
		ext = strings.ToLower(ext)
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		m[ext] = true
	}
	return m
}

// splitAndTrim splits a comma-separated string and trims whitespace.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

