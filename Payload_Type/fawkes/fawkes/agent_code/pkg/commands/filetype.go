package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type FileTypeCommand struct{}

func (c *FileTypeCommand) Name() string { return "file-type" }
func (c *FileTypeCommand) Description() string {
	return "Identify file types by magic bytes (header signatures)"
}

type fileTypeArgs struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"` // Check all files in directory
	MaxFiles  int    `json:"max_files"` // Limit for directory mode (default: 100)
}

type magicSig struct {
	offset  int
	magic   []byte
	desc    string
	ext     string
	category string
}

var magicSignatures = []magicSig{
	// Executables
	{0, []byte{0x4D, 0x5A}, "Windows PE Executable (MZ)", "exe/dll", "executable"},
	{0, []byte{0x7F, 0x45, 0x4C, 0x46}, "ELF Executable", "elf", "executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O 32-bit", "macho", "executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O 64-bit", "macho", "executable"},
	{0, []byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O 64-bit (reversed)", "macho", "executable"},
	{0, []byte{0xCA, 0xFE, 0xBA, 0xBE}, "Mach-O Universal/Java Class", "macho/class", "executable"},
	{0, []byte{0xDE, 0xC0, 0x17, 0x0B}, "macOS DLL (dylib bundle)", "dylib", "executable"},
	// Archives
	{0, []byte{0x50, 0x4B, 0x03, 0x04}, "ZIP Archive", "zip", "archive"},
	{0, []byte{0x50, 0x4B, 0x05, 0x06}, "ZIP Archive (empty)", "zip", "archive"},
	{0, []byte{0x1F, 0x8B}, "Gzip Compressed", "gz", "archive"},
	{0, []byte{0x42, 0x5A, 0x68}, "Bzip2 Compressed", "bz2", "archive"},
	{0, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ Compressed", "xz", "archive"},
	{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip Archive", "7z", "archive"},
	{0, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "RAR Archive", "rar", "archive"},
	// Documents
	{0, []byte{0x25, 0x50, 0x44, 0x46}, "PDF Document", "pdf", "document"},
	{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "Microsoft Office (OLE2)", "doc/xls/ppt", "document"},
	// Images
	{0, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG Image", "png", "image"},
	{0, []byte{0xFF, 0xD8, 0xFF}, "JPEG Image", "jpg", "image"},
	{0, []byte{0x47, 0x49, 0x46, 0x38}, "GIF Image", "gif", "image"},
	{0, []byte{0x42, 0x4D}, "BMP Image", "bmp", "image"},
	{0, []byte{0x49, 0x49, 0x2A, 0x00}, "TIFF Image (little-endian)", "tiff", "image"},
	{0, []byte{0x4D, 0x4D, 0x00, 0x2A}, "TIFF Image (big-endian)", "tiff", "image"},
	// Databases
	{0, []byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74}, "SQLite Database", "sqlite/db", "database"},
	// Crypto/Security
	{0, []byte{0x30, 0x82}, "DER/ASN.1 Certificate or Key", "der/cer/pfx", "crypto"},
	// Disk images
	{0, []byte{0x4C, 0x55, 0x4B, 0x53}, "LUKS Encrypted Volume", "luks", "crypto"},
	{0, []byte{0x2D, 0xB5, 0x2F, 0xFD}, "Zstandard Compressed", "zst", "archive"},
	// Scripts (text-based, check for shebang)
	{0, []byte{0x23, 0x21}, "Script (shebang #!)", "sh/py/rb", "script"},
	// Miscellaneous
	{0, []byte{0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70}, "MP4/MOV Video (ftyp)", "mp4/mov", "media"},
	{0, []byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, "MP4/MOV Video (ftyp)", "mp4/mov", "media"},
	{0, []byte{0x49, 0x44, 0x33}, "MP3 Audio (ID3)", "mp3", "media"},
	{0, []byte{0x4F, 0x67, 0x67, 0x53}, "OGG Container", "ogg", "media"},
	{0, []byte{0x52, 0x49, 0x46, 0x46}, "RIFF Container (WAV/AVI/WebP)", "wav/avi/webp", "media"},
	// Registry
	{0, []byte{0x72, 0x65, 0x67, 0x66}, "Windows Registry Hive", "reg", "system"},
	// Event log
	{0, []byte{0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65}, "Windows Event Log (EVTX)", "evtx", "system"},
}

const fileTypeHeaderSize = 32 // Read first 32 bytes for identification

func (c *FileTypeCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (path). Use -recursive true for directory mode.",
			Status:    "error",
			Completed: true,
		}
	}

	var args fileTypeArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.MaxFiles <= 0 {
		args.MaxFiles = 100
	}

	absPath, err := filepath.Abs(args.Path)
	if err == nil {
		args.Path = absPath
	}

	info, err := os.Stat(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder

	if info.IsDir() {
		count := 0
		err := filepath.Walk(args.Path, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				if err != nil && !fi.IsDir() {
					return nil
				}
				if !args.Recursive && path != args.Path {
					return filepath.SkipDir
				}
				return nil
			}
			if count >= args.MaxFiles {
				return filepath.SkipAll
			}
			result := identifyFile(path, fi)
			sb.WriteString(result)
			count++
			return nil
		})
		if err != nil {
			sb.WriteString(fmt.Sprintf("\nWalk error: %v\n", err))
		}
		sb.WriteString(fmt.Sprintf("\n%d files analyzed", count))
	} else {
		sb.WriteString(identifyFile(args.Path, info))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "completed",
		Completed: true,
	}
}

func identifyFile(path string, info os.FileInfo) string {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("%-50s  ERROR: %v\n", path, err)
	}
	defer f.Close()

	header := make([]byte, fileTypeHeaderSize)
	n, _ := f.Read(header)
	header = header[:n]

	fileType, ext, category := matchMagic(header)
	if fileType == "" {
		// Check if it's likely text
		if isLikelyText(header) {
			fileType = "Text/ASCII"
			ext = "txt"
			category = "text"
		} else {
			fileType = "Unknown binary"
			ext = "?"
			category = "unknown"
		}
	}

	return fmt.Sprintf("%-50s  [%s] %s (%s) %d bytes\n", path, category, fileType, ext, info.Size())
}

func matchMagic(header []byte) (desc, ext, category string) {
	for _, sig := range magicSignatures {
		end := sig.offset + len(sig.magic)
		if end > len(header) {
			continue
		}
		match := true
		for i, b := range sig.magic {
			if header[sig.offset+i] != b {
				match = false
				break
			}
		}
		if match {
			return sig.desc, sig.ext, sig.category
		}
	}
	return "", "", ""
}

func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	textChars := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D {
			textChars++
		}
	}
	return float64(textChars)/float64(len(data)) > 0.85
}
