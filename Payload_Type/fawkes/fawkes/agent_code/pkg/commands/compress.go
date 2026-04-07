package commands

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// Supported archive formats
const (
	formatZip   = "zip"
	formatTarGz = "tar.gz"
)

type CompressCommand struct{}

func (c *CompressCommand) Name() string {
	return "compress"
}

func (c *CompressCommand) Description() string {
	return "Create, list, or extract zip archives for data staging"
}

type CompressParams struct {
	Action   string `json:"action"`
	Path     string `json:"path"`
	Output   string `json:"output"`
	Pattern  string `json:"pattern"`
	Format   string `json:"format"`
	MaxDepth int    `json:"max_depth"`
	MaxSize  int64  `json:"max_size"`
}

// detectFormat determines archive format from params or file extension.
func detectFormat(params CompressParams) string {
	if params.Format != "" {
		return params.Format
	}
	// Auto-detect from path extension for list/extract
	p := strings.ToLower(params.Path)
	if strings.HasSuffix(p, ".tar.gz") || strings.HasSuffix(p, ".tgz") {
		return formatTarGz
	}
	return formatZip
}

func (c *CompressCommand) Execute(task structs.Task) structs.CommandResult {
	var params CompressParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.MaxDepth == 0 {
		params.MaxDepth = 10
	}
	if params.MaxSize == 0 {
		params.MaxSize = 100 * 1024 * 1024 // 100MB default
	}

	format := detectFormat(params)

	switch params.Action {
	case "create":
		if format == formatTarGz {
			return tarGzCreate(task, params)
		}
		return compressCreate(task, params)
	case "list":
		if format == formatTarGz {
			return tarGzList(params)
		}
		return compressList(params)
	case "extract":
		if format == formatTarGz {
			return tarGzExtract(params)
		}
		return compressExtract(params)
	case "stage":
		return compressStage(task, params)
	default:
		return errorf("Unknown action: %s (use 'create', 'list', 'extract', or 'stage')", params.Action)
	}
}

func compressCreate(task structs.Task, params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for create action")
	}

	srcPath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return errorf("Error accessing path: %v", err)
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
		return errorf("Error resolving output path: %v", err)
	}

	// Create zip file
	zipFile, err := os.Create(outputPath)
	if err != nil {
		return errorf("Error creating zip file: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	var fileCount int
	var totalSize int64
	var skipped int
	var fileErrors []string

	if srcInfo.IsDir() {
		baseDir := srcPath
		err = filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, walkErr error) error {
			if task.DidStop() {
				return fmt.Errorf("cancelled")
			}
			if walkErr != nil {
				relName, _ := filepath.Rel(baseDir, path)
				fileErrors = append(fileErrors, fmt.Sprintf("%s: access error: %v", relName, walkErr))
				return nil
			}

			// Skip the output zip file itself
			if path == outputPath {
				return nil
			}

			// Check depth
			relPath, _ := filepath.Rel(baseDir, path)
			depth := len(strings.Split(relPath, string(os.PathSeparator)))
			if depth > params.MaxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip directories (they're created implicitly)
			if d.IsDir() {
				return nil
			}

			// Apply pattern filter
			if params.Pattern != "" {
				matched, matchErr := filepath.Match(params.Pattern, filepath.Base(path))
				if matchErr != nil || !matched {
					return nil
				}
			}

			// Get full file info for entries passing filters
			info, infoErr := d.Info()
			if infoErr != nil {
				relName, _ := filepath.Rel(baseDir, path)
				fileErrors = append(fileErrors, fmt.Sprintf("%s: stat: %v", relName, infoErr))
				return nil
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
				fileErrors = append(fileErrors, fmt.Sprintf("%s: header: %v", relName, headerErr))
				return nil
			}
			header.Name = relName
			header.Method = zip.Deflate

			writer, createErr := zipWriter.CreateHeader(header)
			if createErr != nil {
				fileErrors = append(fileErrors, fmt.Sprintf("%s: create: %v", relName, createErr))
				return nil
			}

			file, openErr := os.Open(path)
			if openErr != nil {
				fileErrors = append(fileErrors, fmt.Sprintf("%s: open: %v", relName, openErr))
				return nil
			}
			defer file.Close()

			written, copyErr := io.Copy(writer, file)
			if copyErr != nil {
				fileErrors = append(fileErrors, fmt.Sprintf("%s: write: %v", relName, copyErr))
				return nil
			}

			fileCount++
			totalSize += written
			return nil
		})

		if err != nil {
			return errorf("Error walking directory: %v", err)
		}
	} else {
		// Single file
		header, headerErr := zip.FileInfoHeader(srcInfo)
		if headerErr != nil {
			return errorf("Error creating file header: %v", headerErr)
		}
		header.Name = filepath.Base(srcPath)
		header.Method = zip.Deflate

		writer, createErr := zipWriter.CreateHeader(header)
		if createErr != nil {
			return errorf("Error creating zip entry: %v", createErr)
		}

		file, openErr := os.Open(srcPath)
		if openErr != nil {
			return errorf("Error opening file: %v", openErr)
		}
		defer file.Close()

		written, copyErr := io.Copy(writer, file)
		if copyErr != nil {
			return errorf("Error writing to zip: %v", copyErr)
		}

		fileCount = 1
		totalSize = written
	}

	// Close writer to flush (writes central directory)
	if closeErr := zipWriter.Close(); closeErr != nil {
		return errorf("Error finalizing zip archive: %v", closeErr)
	}

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
	if len(fileErrors) > 0 {
		result += fmt.Sprintf("\n\n--- %d file errors ---\n", len(fileErrors))
		for _, e := range fileErrors {
			result += fmt.Sprintf("  %s\n", e)
		}
	}

	return successResult(result)
}

func compressList(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for list action")
	}

	zipPath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return errorf("Error opening zip: %v", err)
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

	return successResult(sb.String())
}

func compressExtract(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for extract action")
	}

	zipPath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return errorf("Error opening zip: %v", err)
	}
	defer reader.Close()

	// Determine output directory
	outputDir := params.Output
	if outputDir == "" {
		outputDir = strings.TrimSuffix(zipPath, filepath.Ext(zipPath))
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return errorf("Error resolving output path: %v", err)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return errorf("Error creating output directory: %v", err)
	}

	var extracted int
	var totalSize int64
	var extractErrors []string

	for _, f := range reader.File {
		// Sanitize path to prevent zip slip
		destPath := filepath.Join(outputDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(outputDir)+string(os.PathSeparator)) && filepath.Clean(destPath) != filepath.Clean(outputDir) {
			extractErrors = append(extractErrors, fmt.Sprintf("%s: skipped (path traversal)", f.Name))
			continue
		}

		if f.FileInfo().IsDir() {
			if mkErr := os.MkdirAll(destPath, f.Mode()); mkErr != nil {
				extractErrors = append(extractErrors, fmt.Sprintf("%s: mkdir: %v", f.Name, mkErr))
			}
			continue
		}

		// Ensure parent directory exists
		if mkErr := os.MkdirAll(filepath.Dir(destPath), 0755); mkErr != nil {
			extractErrors = append(extractErrors, fmt.Sprintf("%s: mkdir parent: %v", f.Name, mkErr))
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
			extractErrors = append(extractErrors, fmt.Sprintf("%s: open: %v", f.Name, openErr))
			continue
		}

		outFile, createErr := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if createErr != nil {
			rc.Close()
			extractErrors = append(extractErrors, fmt.Sprintf("%s: create: %v", f.Name, createErr))
			continue
		}

		written, copyErr := io.Copy(outFile, rc)
		closeErr := outFile.Close()
		rc.Close()

		if copyErr != nil {
			extractErrors = append(extractErrors, fmt.Sprintf("%s: write: %v", f.Name, copyErr))
			continue
		}
		if closeErr != nil {
			extractErrors = append(extractErrors, fmt.Sprintf("%s: close: %v", f.Name, closeErr))
			continue
		}

		extracted++
		totalSize += written
	}

	result := fmt.Sprintf("Extracted %d files (%s) to %s", extracted, formatFileSize(totalSize), outputDir)
	if len(extractErrors) > 0 {
		result += fmt.Sprintf("\n\n--- %d errors ---\n", len(extractErrors))
		for _, e := range extractErrors {
			result += fmt.Sprintf("  %s\n", e)
		}
	}
	return successResult(result)
}
