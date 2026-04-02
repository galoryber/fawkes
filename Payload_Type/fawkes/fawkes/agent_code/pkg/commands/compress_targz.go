package commands

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

func tarGzCreate(task structs.Task, params CompressParams) structs.CommandResult {
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

	outputPath := params.Output
	if outputPath == "" {
		if srcInfo.IsDir() {
			outputPath = srcPath + ".tar.gz"
		} else {
			outputPath = strings.TrimSuffix(srcPath, filepath.Ext(srcPath)) + ".tar.gz"
		}
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return errorf("Error resolving output path: %v", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return errorf("Error creating archive file: %v", err)
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

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

			if path == outputPath {
				return nil
			}

			relPath, _ := filepath.Rel(baseDir, path)
			depth := len(strings.Split(relPath, string(os.PathSeparator)))
			if depth > params.MaxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				return nil
			}

			if params.Pattern != "" {
				matched, matchErr := filepath.Match(params.Pattern, filepath.Base(path))
				if matchErr != nil || !matched {
					return nil
				}
			}

			info, infoErr := d.Info()
			if infoErr != nil {
				relName, _ := filepath.Rel(baseDir, path)
				fileErrors = append(fileErrors, fmt.Sprintf("%s: stat: %v", relName, infoErr))
				return nil
			}

			if info.Size() > params.MaxSize {
				skipped++
				return nil
			}

			relName, _ := filepath.Rel(baseDir, path)
			relName = filepath.ToSlash(relName)

			header, headerErr := tar.FileInfoHeader(info, "")
			if headerErr != nil {
				fileErrors = append(fileErrors, fmt.Sprintf("%s: header: %v", relName, headerErr))
				return nil
			}
			header.Name = relName

			if writeErr := tarWriter.WriteHeader(header); writeErr != nil {
				fileErrors = append(fileErrors, fmt.Sprintf("%s: write header: %v", relName, writeErr))
				return nil
			}

			file, openErr := os.Open(path)
			if openErr != nil {
				fileErrors = append(fileErrors, fmt.Sprintf("%s: open: %v", relName, openErr))
				return nil
			}
			defer file.Close()

			written, copyErr := io.Copy(tarWriter, file)
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
		header, headerErr := tar.FileInfoHeader(srcInfo, "")
		if headerErr != nil {
			return errorf("Error creating file header: %v", headerErr)
		}
		header.Name = filepath.Base(srcPath)

		if err := tarWriter.WriteHeader(header); err != nil {
			return errorf("Error writing tar header: %v", err)
		}

		file, openErr := os.Open(srcPath)
		if openErr != nil {
			return errorf("Error opening file: %v", openErr)
		}
		defer file.Close()

		written, copyErr := io.Copy(tarWriter, file)
		if copyErr != nil {
			return errorf("Error writing to archive: %v", copyErr)
		}

		fileCount = 1
		totalSize = written
	}

	if closeErr := tarWriter.Close(); closeErr != nil {
		return errorf("Error finalizing tar archive: %v", closeErr)
	}
	if closeErr := gzWriter.Close(); closeErr != nil {
		return errorf("Error finalizing gzip: %v", closeErr)
	}

	archiveStat, _ := os.Stat(outputPath)
	archiveSize := int64(0)
	if archiveStat != nil {
		archiveSize = archiveStat.Size()
	}

	result := fmt.Sprintf("Archive created: %s\nFiles: %d | Original: %s | Compressed: %s",
		outputPath, fileCount, formatFileSize(totalSize), formatFileSize(archiveSize))
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

func tarGzList(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for list action")
	}

	archivePath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	file, err := os.Open(archivePath)
	if err != nil {
		return errorf("Error opening archive: %v", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return errorf("Error reading gzip: %v", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	var sb strings.Builder
	var totalSize int64
	var fileCount int

	sb.WriteString(fmt.Sprintf("%-12s %-10s %-20s %s\n", "Size", "Mode", "Modified", "Name"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for {
		header, readErr := tarReader.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errorf("Error reading tar entry: %v", readErr)
		}

		sb.WriteString(fmt.Sprintf("%-12s %-10s %-20s %s\n",
			formatFileSize(header.Size),
			header.FileInfo().Mode().String(),
			header.ModTime.Format("2006-01-02 15:04:05"),
			header.Name))
		totalSize += header.Size
		fileCount++
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n")
	sb.WriteString(fmt.Sprintf("%d entries | Total: %s", fileCount, formatFileSize(totalSize)))

	archiveStat, _ := os.Stat(archivePath)
	if archiveStat != nil && totalSize > 0 {
		ratio := (1 - float64(archiveStat.Size())/float64(totalSize)) * 100
		sb.WriteString(fmt.Sprintf(" | Compressed: %s | Ratio: %.1f%%",
			formatFileSize(archiveStat.Size()), ratio))
	}

	return successResult(sb.String())
}

func tarGzExtract(params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for extract action")
	}

	archivePath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	file, err := os.Open(archivePath)
	if err != nil {
		return errorf("Error opening archive: %v", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return errorf("Error reading gzip: %v", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	outputDir := params.Output
	if outputDir == "" {
		// Strip .tar.gz or .tgz extension
		base := archivePath
		if strings.HasSuffix(strings.ToLower(base), ".tar.gz") {
			base = base[:len(base)-7]
		} else if strings.HasSuffix(strings.ToLower(base), ".tgz") {
			base = base[:len(base)-4]
		}
		outputDir = base
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

	for {
		header, readErr := tarReader.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errorf("Error reading tar entry: %v", readErr)
		}

		// Sanitize path to prevent traversal
		cleanName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			extractErrors = append(extractErrors, fmt.Sprintf("%s: skipped (path traversal)", header.Name))
			continue
		}
		destPath := filepath.Join(outputDir, cleanName)
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(outputDir)+string(os.PathSeparator)) && filepath.Clean(destPath) != filepath.Clean(outputDir) {
			extractErrors = append(extractErrors, fmt.Sprintf("%s: skipped (path traversal)", header.Name))
			continue
		}

		// Apply pattern filter
		if params.Pattern != "" {
			matched, matchErr := filepath.Match(params.Pattern, filepath.Base(header.Name))
			if matchErr != nil || !matched {
				continue
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if mkErr := os.MkdirAll(destPath, os.FileMode(header.Mode)); mkErr != nil {
				extractErrors = append(extractErrors, fmt.Sprintf("%s: mkdir: %v", header.Name, mkErr))
			}
		case tar.TypeReg:
			if mkErr := os.MkdirAll(filepath.Dir(destPath), 0755); mkErr != nil {
				extractErrors = append(extractErrors, fmt.Sprintf("%s: mkdir parent: %v", header.Name, mkErr))
				continue
			}

			outFile, createErr := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if createErr != nil {
				extractErrors = append(extractErrors, fmt.Sprintf("%s: create: %v", header.Name, createErr))
				continue
			}

			written, copyErr := io.Copy(outFile, tarReader)
			closeErr := outFile.Close()

			if copyErr != nil {
				extractErrors = append(extractErrors, fmt.Sprintf("%s: write: %v", header.Name, copyErr))
				continue
			}
			if closeErr != nil {
				extractErrors = append(extractErrors, fmt.Sprintf("%s: close: %v", header.Name, closeErr))
				continue
			}

			extracted++
			totalSize += written
		case tar.TypeSymlink:
			// Skip symlinks for security
			extractErrors = append(extractErrors, fmt.Sprintf("%s: skipped (symlink)", header.Name))
		default:
			extractErrors = append(extractErrors, fmt.Sprintf("%s: skipped (unsupported type %d)", header.Name, header.Typeflag))
		}
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
