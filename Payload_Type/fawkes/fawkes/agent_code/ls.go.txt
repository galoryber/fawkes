package commands

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	structs "github.com/MythicMeta/MythicContainer/agent_structs"
)

type lsArgs struct {
	RemotePath string `json:"remote_path"`
}

// Run - interface method that retrieves a process list
func Run(task structs.Task) {
	msg := task.NewResponse()

	// directory or location
	args := lsArgs{}

	// Get the directory path from the arguments
	dirPath := args.RemotePath

	// Read the directory
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		log.Fatalf("Error reading directory: %v", err)
	}

	// Separate directories and files
	var dirs []os.FileInfo
	var regularFiles []os.FileInfo
	for _, file := range files {
		if file.IsDir() {
			dirs = append(dirs, file)
		} else {
			regularFiles = append(regularFiles, file)
		}
	}

	// Combine directories and files, with directories first
	sortedFiles := append(dirs, regularFiles...)

	// Print the contents with additional attributes
	fmt.Printf("Contents of directory: %s\n", dirPath)
	fmt.Printf("%-30s %-10s %-20s %s\n", "Name", "Type", "Size (bytes)", "Last Modified")
	fmt.Println(strings.Repeat("-", 80))
	for _, file := range sortedFiles {
		fileType := "FILE"
		if file.IsDir() {
			fileType = "DIR"
		}
		fmt.Printf(
			"%-30s %-10s %-20d %s\n",
			file.Name(),
			fileType,
			file.Size(),
			file.ModTime().Format("2006-01-02 15:04:05"),
		)
	}

}
