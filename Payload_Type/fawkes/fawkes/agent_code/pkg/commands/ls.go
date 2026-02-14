package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"fawkes/pkg/structs"
)

// LsCommand implements the ls command
type LsCommand struct{}

// Name returns the command name
func (c *LsCommand) Name() string {
	return "ls"
}

// Description returns the command description
func (c *LsCommand) Description() string {
	return "List directory contents"
}

// Execute executes the ls command
func (c *LsCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var args struct {
		Path       string `json:"path"`
		FileBrowser bool   `json:"file_browser"`
	}

	// Default to current directory if no parameters
	if task.Params == "" {
		args.Path = "."
	} else {
		// Try to parse as JSON first
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// If not JSON, treat as simple string path
			args.Path = task.Params
		}
	}

	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data")
	args.Path = stripPathQuotes(args.Path)

	// Ensure we have a path
	if args.Path == "" {
		args.Path = "."
	}

	// Execute ls
	result := performLs(args.Path)
	
	// Format response based on file browser flag
	if args.FileBrowser {
		// Return JSON for file browser
		jsonBytes, err := json.Marshal(result)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to marshal ls result: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		
		return structs.CommandResult{
			Output:    string(jsonBytes),
			Status:    "success",
			Completed: true,
		}
	}

	// Return formatted text output
	return structs.CommandResult{
		Output:    formatLsOutput(result),
		Status:    "success", 
		Completed: true,
	}
}

func performLs(path string) structs.FileListing {
	result := structs.FileListing{
		Host:       getHostname(),
		IsFile:     false,
		Name:       filepath.Base(path),
		ParentPath: filepath.Dir(path),
		Success:    true,
		Files:      []structs.FileListEntry{},
	}

	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		result.Success = false
		return result
	}

	// If it's a file, return info about the file
	if !info.IsDir() {
		result.IsFile = true
		fileEntry := structs.FileListEntry{
			Name:         info.Name(),
			FullName:     path,
			IsFile:       true,
			Size:         info.Size(),
			ModifyTime:   info.ModTime(),
			AccessTime:   info.ModTime(), // Simplified
			CreationDate: info.ModTime(), // Simplified
			Owner:        "unknown",      // Would need OS-specific code
			Group:        "unknown",      // Would need OS-specific code
			Permissions:  info.Mode().String(),
		}
		result.Files = []structs.FileListEntry{fileEntry}
		return result
	}

	// It's a directory, list contents
	entries, err := os.ReadDir(path)
	if err != nil {
		result.Success = false
		return result
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue // Skip entries we can't stat
		}

		fileEntry := structs.FileListEntry{
			Name:         entry.Name(),
			FullName:     fullPath,
			IsFile:       !entry.IsDir(),
			Size:         info.Size(),
			ModifyTime:   info.ModTime(),
			AccessTime:   info.ModTime(), // Simplified
			CreationDate: info.ModTime(), // Simplified
			Owner:        "unknown",      // Would need OS-specific code
			Group:        "unknown",      // Would need OS-specific code
			Permissions:  info.Mode().String(),
		}

		result.Files = append(result.Files, fileEntry)
	}

	return result
}

func formatLsOutput(result structs.FileListing) string {
	if !result.Success {
		return fmt.Sprintf("Failed to list directory: %s", result.ParentPath)
	}

	output := fmt.Sprintf("Contents of directory: %s\n", result.ParentPath)
	output += fmt.Sprintf("%-30s %-10s %-15s %s\n", "Name", "Type", "Size", "Modified")
	output += "--------------------------------------------------------------------------------\n"

	for _, file := range result.Files {
		fileType := "FILE"
		if !file.IsFile {
			fileType = "DIR"
		}
		
		output += fmt.Sprintf("%-30s %-10s %-15d %s\n",
			file.Name,
			fileType,
			file.Size,
			file.ModifyTime.Format("2006-01-02 15:04:05"),
		)
	}

	return output
}

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}