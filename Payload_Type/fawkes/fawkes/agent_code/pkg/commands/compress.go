package commands

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type CompressCommand struct{}

func (c *CompressCommand) Name() string {
	return "compress"
}

func (c *CompressCommand) Description() string {
	return "Create, list, or extract zip archives for data staging"
}

type CompressParams struct {
	Action    string `json:"action"`
	Path      string `json:"path"`
	Output    string `json:"output"`
	Pattern   string `json:"pattern"`
	MaxDepth  int    `json:"max_depth"`
	MaxSize   int64  `json:"max_size"`
}

func (c *CompressCommand) Execute(task structs.Task) structs.CommandResult {
	var params CompressParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.MaxDepth == 0 {
		params.MaxDepth = 10
	}
	if params.MaxSize == 0 {
		params.MaxSize = 100 * 1024 * 1024 // 100MB default
	}

	switch params.Action {
	case "create":
		return compressCreate(params)
	case "list":
		return compressList(params)
	case "extract":
		return compressExtract(params)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'create', 'list', or 'extract')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func compressCreate(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return structs.CommandResult{
			Output:    "Error: 'path' is required for create action",
			Status:    "error",
			Completed: true,
		}
	}

	srcPath, err := filepath.Abs(params.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error accessing path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine output path
	outputPath := params.Output
	if outputPath == "" {
		if srcInfo.IsDir() {
			outputPath = srcPath + ".zip"
		} else {
			outputPath = strings.TrimSuffix(srcPath, filepath.Ext(srcPath)) + ".zip"
		}
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving output path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Create zip file
	zipFile, err := os.Create(outputPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating zip file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	var fileCount int
	var totalSize int64
	var skipped int

	if srcInfo.IsDir() {
		baseDir := srcPath
		err = filepath.Walk(srcPath, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil // skip inaccessible files
			}

			// Skip the output zip file itself
			if path == outputPath {
				return nil
			}

			// Check depth
			relPath, _ := filepath.Rel(baseDir, path)
			depth := len(strings.Split(relPath, string(os.PathSeparator)))
			if depth > params.MaxDepth {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip directories (they're created implicitly)
			if info.IsDir() {
				return nil
			}

			// Apply pattern filter
			if params.Pattern != "" {
				matched, matchErr := filepath.Match(params.Pattern, info.Name())
				if matchErr != nil || !matched {
					return nil
				}
			}

			// Check file size
			if info.Size() > params.MaxSize {
				skipped++
				return nil
			}

			// Add to zip
			relName, _ := filepath.Rel(baseDir, path)
			// Normalize to forward slashes for zip
			relName = filepath.ToSlash(relName)

			header, headerErr := zip.FileInfoHeader(info)
			if headerErr != nil {
				return nil
			}
			header.Name = relName
			header.Method = zip.Deflate

			writer, createErr := zipWriter.CreateHeader(header)
			if createErr != nil {
				return nil
			}

			file, openErr := os.Open(path)
			if openErr != nil {
				return nil
			}
			defer file.Close()

			written, copyErr := io.Copy(writer, file)
			if copyErr != nil {
				return nil
			}

			fileCount++
			totalSize += written
			return nil
		})

		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error walking directory: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		// Single file
		header, headerErr := zip.FileInfoHeader(srcInfo)
		if headerErr != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating file header: %v", headerErr),
				Status:    "error",
				Completed: true,
			}
		}
		header.Name = filepath.Base(srcPath)
		header.Method = zip.Deflate

		writer, createErr := zipWriter.CreateHeader(header)
		if createErr != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating zip entry: %v", createErr),
				Status:    "error",
				Completed: true,
			}
		}

		file, openErr := os.Open(srcPath)
		if openErr != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error opening file: %v", openErr),
				Status:    "error",
				Completed: true,
			}
		}
		defer file.Close()

		written, copyErr := io.Copy(writer, file)
		if copyErr != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error writing to zip: %v", copyErr),
				Status:    "error",
				Completed: true,
			}
		}

		fileCount = 1
		totalSize = written
	}

	// Close writer to flush
	zipWriter.Close()

	// Get final zip size
	zipStat, _ := os.Stat(outputPath)
	zipSize := int64(0)
	if zipStat != nil {
		zipSize = zipStat.Size()
	}

	result := fmt.Sprintf("Archive created: %s\nFiles: %d | Original: %s | Compressed: %s",
		outputPath, fileCount, formatFileSize(totalSize), formatFileSize(zipSize))
	if skipped > 0 {
		result += fmt.Sprintf(" | Skipped: %d (exceeded max_size)", skipped)
	}

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

func compressList(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return structs.CommandResult{
			Output:    "Error: 'path' is required for list action",
			Status:    "error",
			Completed: true,
		}
	}

	zipPath, err := filepath.Abs(params.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening zip: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer reader.Close()

	var sb strings.Builder
	var totalUncompressed uint64
	var totalCompressed uint64

	sb.WriteString(fmt.Sprintf("%-12s %-12s %-20s %s\n", "Size", "Compressed", "Modified", "Name"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, f := range reader.File {
		sb.WriteString(fmt.Sprintf("%-12s %-12s %-20s %s\n",
			formatFileSize(int64(f.UncompressedSize64)),
			formatFileSize(int64(f.CompressedSize64)),
			f.Modified.Format("2006-01-02 15:04:05"),
			f.Name))
		totalUncompressed += f.UncompressedSize64
		totalCompressed += f.CompressedSize64
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n")
	sb.WriteString(fmt.Sprintf("%d files | Total: %s | Compressed: %s",
		len(reader.File), formatFileSize(int64(totalUncompressed)), formatFileSize(int64(totalCompressed))))

	ratio := float64(0)
	if totalUncompressed > 0 {
		ratio = (1 - float64(totalCompressed)/float64(totalUncompressed)) * 100
	}
	sb.WriteString(fmt.Sprintf(" | Ratio: %.1f%%", ratio))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func compressExtract(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return structs.CommandResult{
			Output:    "Error: 'path' is required for extract action",
			Status:    "error",
			Completed: true,
		}
	}

	zipPath, err := filepath.Abs(params.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening zip: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer reader.Close()

	// Determine output directory
	outputDir := params.Output
	if outputDir == "" {
		outputDir = strings.TrimSuffix(zipPath, filepath.Ext(zipPath))
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving output path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating output directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var extracted int
	var totalSize int64

	for _, f := range reader.File {
		// Sanitize path to prevent zip slip
		destPath := filepath.Join(outputDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(outputDir)+string(os.PathSeparator)) && filepath.Clean(destPath) != filepath.Clean(outputDir) {
			continue // skip malicious paths
		}

		if f.FileInfo().IsDir() {
			if mkErr := os.MkdirAll(destPath, f.Mode()); mkErr != nil {
				continue
			}
			continue
		}

		// Ensure parent directory exists
		if mkErr := os.MkdirAll(filepath.Dir(destPath), 0755); mkErr != nil {
			continue
		}

		// Apply pattern filter
		if params.Pattern != "" {
			matched, matchErr := filepath.Match(params.Pattern, filepath.Base(f.Name))
			if matchErr != nil || !matched {
				continue
			}
		}

		rc, openErr := f.Open()
		if openErr != nil {
			continue
		}

		outFile, createErr := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if createErr != nil {
			rc.Close()
			continue
		}

		written, copyErr := io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if copyErr != nil {
			continue
		}

		extracted++
		totalSize += written
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Extracted %d files (%s) to %s", extracted, formatFileSize(totalSize), outputDir),
		Status:    "success",
		Completed: true,
	}
}

