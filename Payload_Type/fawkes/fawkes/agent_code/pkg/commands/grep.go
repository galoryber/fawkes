package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fawkes/pkg/structs"
)

// GrepCommand searches file contents for patterns
type GrepCommand struct{}

func (c *GrepCommand) Name() string { return "grep" }
func (c *GrepCommand) Description() string {
	return "Search file contents for patterns (T1083, T1552.001)"
}

type grepArgs struct {
	Pattern     string `json:"pattern"`
	Path        string `json:"path"`
	Recursive   bool   `json:"recursive"`
	MaxDepth    int    `json:"max_depth"`
	MaxResults  int    `json:"max_results"`
	Context     int    `json:"context"`
	Extensions  string `json:"extensions"`
	IgnoreCase  bool   `json:"ignore_case"`
	MaxFileSize int64  `json:"max_file_size"`
}

type grepMatch struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Content string `json:"content"`
}

func (c *GrepCommand) Execute(task structs.Task) structs.CommandResult {
	var args grepArgs
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Usage: grep -pattern <regex> [-path <dir>] [-extensions .txt,.xml] [-ignore_case] [-max_results 100]",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Pattern == "" {
		return structs.CommandResult{
			Output:    "Error: pattern is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Set defaults
	if args.Path == "" {
		args.Path = "."
	}
	if args.MaxDepth <= 0 {
		args.MaxDepth = 10
	}
	if args.MaxResults <= 0 {
		args.MaxResults = 100
	}
	if args.MaxFileSize <= 0 {
		args.MaxFileSize = 10 * 1024 * 1024 // 10 MB
	}

	// Compile regex
	regexPattern := args.Pattern
	if args.IgnoreCase {
		regexPattern = "(?i)" + regexPattern
	}
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: invalid regex pattern: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Parse extension filter
	var extFilter map[string]bool
	if args.Extensions != "" {
		extFilter = make(map[string]bool)
		for _, ext := range strings.Split(args.Extensions, ",") {
			ext = strings.TrimSpace(ext)
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extFilter[strings.ToLower(ext)] = true
		}
	}

	// Resolve start path
	startPath, err := filepath.Abs(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Check if path is a single file
	info, err := os.Stat(startPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var matches []grepMatch
	filesSearched := 0

	if !info.IsDir() {
		// Search single file
		fileMatches := searchFile(startPath, re, args.Context, args.MaxResults)
		matches = append(matches, fileMatches...)
		filesSearched = 1
	} else {
		// Walk directory
		startDepth := strings.Count(startPath, string(os.PathSeparator))
		_ = filepath.WalkDir(startPath, func(path string, d os.DirEntry, err error) error {
			if task.DidStop() {
				return fmt.Errorf("cancelled")
			}
			if err != nil {
				return nil // Skip inaccessible dirs
			}

			// Check depth
			depth := strings.Count(path, string(os.PathSeparator)) - startDepth
			if depth > args.MaxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				// Skip hidden dirs and common large/binary dirs
				name := d.Name()
				if strings.HasPrefix(name, ".") && name != "." {
					return filepath.SkipDir
				}
				if name == "node_modules" || name == "__pycache__" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			// Check extension filter
			if extFilter != nil {
				ext := strings.ToLower(filepath.Ext(path))
				if !extFilter[ext] {
					return nil
				}
			}

			// Skip binary/large files
			finfo, err := d.Info()
			if err != nil {
				return nil
			}
			if finfo.Size() > args.MaxFileSize || finfo.Size() == 0 {
				return nil
			}

			// Skip likely binary files by extension
			if isBinaryExtension(filepath.Ext(path)) {
				return nil
			}

			filesSearched++
			fileMatches := searchFile(path, re, args.Context, args.MaxResults-len(matches))
			matches = append(matches, fileMatches...)

			if len(matches) >= args.MaxResults {
				return fmt.Errorf("max results reached")
			}
			return nil
		})
	}

	if len(matches) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No matches found for pattern %q in %s (%d files searched)", args.Pattern, startPath, filesSearched),
			Status:    "success",
			Completed: true,
		}
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d matches in %s (%d files searched):\n\n", len(matches), startPath, filesSearched))

	currentFile := ""
	for _, m := range matches {
		if m.File != currentFile {
			if currentFile != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("=== %s ===\n", m.File))
			currentFile = m.File
		}
		sb.WriteString(fmt.Sprintf("%d: %s\n", m.Line, m.Content))
	}

	if len(matches) >= args.MaxResults {
		sb.WriteString(fmt.Sprintf("\n[Results truncated at %d matches]", args.MaxResults))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func searchFile(path string, re *regexp.Regexp, contextLines int, maxResults int) []grepMatch {
	if maxResults <= 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var matches []grepMatch
	var lines []string

	scanner := bufio.NewScanner(f)
	// Increase buffer for long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lines = append(lines, line)

		if re.MatchString(line) {
			// Add context before
			if contextLines > 0 {
				startCtx := len(lines) - 1 - contextLines
				if startCtx < 0 {
					startCtx = 0
				}
				for i := startCtx; i < len(lines)-1; i++ {
					ctxLineNum := lineNum - (len(lines) - 1 - i)
					matches = append(matches, grepMatch{
						File:    path,
						Line:    ctxLineNum,
						Content: lines[i],
					})
				}
			}

			// Add the matching line
			matches = append(matches, grepMatch{
				File:    path,
				Line:    lineNum,
				Content: line,
			})

			if len(matches) >= maxResults {
				break
			}
		}

		// Keep only enough lines for context
		if contextLines > 0 && len(lines) > contextLines+1 {
			lines = lines[len(lines)-contextLines-1:]
		}
	}

	return matches
}

func isBinaryExtension(ext string) bool {
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".obj": true, ".o": true,
		".class": true, ".jar": true, ".war": true,
		".zip": true, ".gz": true, ".tar": true, ".bz2": true,
		".7z": true, ".rar": true, ".xz": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".bmp": true, ".ico": true, ".svg": true, ".webp": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
		".wav": true, ".flac": true, ".mov": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true,
		".xlsx": true, ".ppt": true, ".pptx": true,
		".pyc": true, ".pyo": true, ".wasm": true,
		".ttf": true, ".woff": true, ".woff2": true, ".eot": true,
		".db": true, ".sqlite": true, ".mdb": true,
	}
	return binaryExts[strings.ToLower(ext)]
}
