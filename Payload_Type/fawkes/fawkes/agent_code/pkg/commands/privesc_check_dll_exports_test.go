package commands

import (
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPeTypeStr(t *testing.T) {
	if peTypeStr(true) != "DLL" {
		t.Error("expected DLL")
	}
	if peTypeStr(false) != "EXE" {
		t.Error("expected EXE")
	}
}

func TestParseExportDirectory_MinimalPE(t *testing.T) {
	// Build a minimal PE with one export in a temp file, then parse it.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dll")

	peData := buildMinimalPEWithExport("TestFunc", 1)
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer peFile.Close()

	var exportDir pe.DataDirectory
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		exportDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	case *pe.OptionalHeader32:
		exportDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	}

	if exportDir.VirtualAddress == 0 {
		t.Fatal("no export directory in test PE")
	}

	exports, dllName, err := parseExportDirectory(peFile, exportDir)
	if err != nil {
		t.Fatalf("parseExportDirectory: %v", err)
	}

	if dllName != "test.dll" {
		t.Errorf("dllName = %q, want test.dll", dllName)
	}

	if len(exports) != 1 {
		t.Fatalf("expected 1 export, got %d", len(exports))
	}

	if exports[0].name != "TestFunc" {
		t.Errorf("export name = %q, want TestFunc", exports[0].name)
	}
	if exports[0].ordinal != 1 {
		t.Errorf("export ordinal = %d, want 1", exports[0].ordinal)
	}
}

func TestParseExportDirectory_NoExports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noexport.exe")

	peData := buildMinimalPENoExport()
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer peFile.Close()

	var exportDir pe.DataDirectory
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		exportDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	case *pe.OptionalHeader32:
		exportDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	}

	if exportDir.VirtualAddress != 0 || exportDir.Size != 0 {
		t.Fatal("test PE should have no exports")
	}
}

func TestFindSectionByRVA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dll")

	peData := buildMinimalPEWithExport("Fn", 1)
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer peFile.Close()

	// Should find the .text section (which starts at RVA 0x1000 in our test PE)
	s := findSectionByRVA(peFile, 0x1000)
	if s == nil {
		t.Fatal("expected to find section at RVA 0x1000")
	}

	// Should not find anything at a high RVA
	s = findSectionByRVA(peFile, 0xFFFF0000)
	if s != nil {
		t.Fatal("should not find section at invalid RVA")
	}
}

func TestRvaToOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dll")

	peData := buildMinimalPEWithExport("Fn", 1)
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer peFile.Close()

	off := rvaToOffset(peFile, 0x1000)
	if off < 0 {
		t.Error("expected valid offset for RVA 0x1000")
	}

	off = rvaToOffset(peFile, 0xDEAD0000)
	if off >= 0 {
		t.Error("expected -1 for invalid RVA")
	}
}

// buildMinimalPE creates a minimal valid PE64 with no exports.
func buildMinimalPENoExport() []byte {
	buf := make([]byte, 0x400)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80) // e_lfanew

	// PE signature
	copy(buf[0x80:], []byte("PE\x00\x00"))

	// COFF header (20 bytes)
	coff := buf[0x84:]
	binary.LittleEndian.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint16(coff[2:], 1)    // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], 0xF0) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], 0x22) // Characteristics (EXE, large address aware)

	// Optional header (PE32+)
	opt := buf[0x98:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)  // PE32+ magic
	binary.LittleEndian.PutUint32(opt[56:], 0x1000) // SectionAlignment
	binary.LittleEndian.PutUint32(opt[60:], 0x200)  // FileAlignment
	binary.LittleEndian.PutUint32(opt[16:], 0x1000) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[24:], 0x1000) // ImageBase (low)
	binary.LittleEndian.PutUint32(opt[80:], 0x2000) // SizeOfImage
	binary.LittleEndian.PutUint32(opt[84:], 0x200)  // SizeOfHeaders
	binary.LittleEndian.PutUint32(opt[108:], 16)    // NumberOfRvaAndSizes

	// Data directories are all zero (no exports)

	// Section header (.text) at offset 0x188
	sect := buf[0x188:]
	copy(sect[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sect[8:], 0x100)  // VirtualSize
	binary.LittleEndian.PutUint32(sect[12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(sect[16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(sect[20:], 0x200)  // PointerToRawData
	binary.LittleEndian.PutUint32(sect[36:], 0x60000020) // Characteristics (code, exec, read)

	return buf
}

// buildMinimalPEWithExport creates a PE64 DLL with a single named export.
func buildMinimalPEWithExport(funcName string, ordinal uint32) []byte {
	buf := make([]byte, 0x600)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80)

	// PE signature
	copy(buf[0x80:], []byte("PE\x00\x00"))

	// COFF header
	coff := buf[0x84:]
	binary.LittleEndian.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint16(coff[2:], 1)     // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], 0xF0)  // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], 0x2022) // Characteristics (DLL, EXE, large addr)

	// Optional header (PE32+)
	opt := buf[0x98:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)  // PE32+ magic
	binary.LittleEndian.PutUint32(opt[56:], 0x1000) // SectionAlignment
	binary.LittleEndian.PutUint32(opt[60:], 0x200)  // FileAlignment
	binary.LittleEndian.PutUint32(opt[16:], 0x1000) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[24:], 0x1000) // ImageBase (low)
	binary.LittleEndian.PutUint32(opt[80:], 0x2000) // SizeOfImage
	binary.LittleEndian.PutUint32(opt[84:], 0x200)  // SizeOfHeaders
	binary.LittleEndian.PutUint32(opt[108:], 16)    // NumberOfRvaAndSizes

	// Data directory[0] = Export directory
	dd := opt[112:] // Start of data directories
	binary.LittleEndian.PutUint32(dd[0:], 0x1000) // Export dir RVA (in .text section)
	binary.LittleEndian.PutUint32(dd[4:], 0x100)  // Export dir Size

	// Section header (.text) at offset 0x188
	sect := buf[0x188:]
	copy(sect[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sect[8:], 0x200)  // VirtualSize
	binary.LittleEndian.PutUint32(sect[12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(sect[16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(sect[20:], 0x200)  // PointerToRawData
	binary.LittleEndian.PutUint32(sect[36:], 0x60000020) // code, exec, read

	// Export directory at file offset 0x200 (RVA 0x1000)
	expDir := buf[0x200:]
	// IMAGE_EXPORT_DIRECTORY layout (40 bytes):
	// +0:  Characteristics (0)
	// +4:  TimeDateStamp
	// +8:  MajorVersion, MinorVersion
	// +12: Name RVA
	// +16: OrdinalBase
	// +20: NumberOfFunctions
	// +24: NumberOfNames
	// +28: AddressOfFunctions RVA
	// +32: AddressOfNames RVA
	// +36: AddressOfNameOrdinals RVA

	nameStr := "test.dll"
	funcNameStr := funcName

	// Layout in section data (all relative to section start at file 0x200 / RVA 0x1000):
	// 0x00-0x27: Export directory (40 bytes)
	// 0x28-0x2B: AddressOfFunctions array (1 entry, 4 bytes)
	// 0x2C-0x2F: AddressOfNames array (1 entry, 4 bytes)
	// 0x30-0x31: AddressOfNameOrdinals array (1 entry, 2 bytes)
	// 0x40-0x48: "test.dll\0"
	// 0x50-...:  funcName + "\0"
	// 0x80:      fake function RVA target

	addrOfFunctions := uint32(0x1028)    // RVA of functions array
	addrOfNames := uint32(0x102C)        // RVA of names array
	addrOfNameOrdinals := uint32(0x1030) // RVA of ordinals array
	nameRVA := uint32(0x1040)            // RVA of "test.dll" string
	funcNameRVA := uint32(0x1050)        // RVA of function name string
	funcTargetRVA := uint32(0x1080)      // Fake target address (outside export dir)

	binary.LittleEndian.PutUint32(expDir[12:], nameRVA)           // Name
	binary.LittleEndian.PutUint32(expDir[16:], ordinal)           // OrdinalBase
	binary.LittleEndian.PutUint32(expDir[20:], 1)                 // NumberOfFunctions
	binary.LittleEndian.PutUint32(expDir[24:], 1)                 // NumberOfNames
	binary.LittleEndian.PutUint32(expDir[28:], addrOfFunctions)   // AddressOfFunctions
	binary.LittleEndian.PutUint32(expDir[32:], addrOfNames)       // AddressOfNames
	binary.LittleEndian.PutUint32(expDir[36:], addrOfNameOrdinals) // AddressOfNameOrdinals

	// Functions array: 1 entry pointing to fake target
	binary.LittleEndian.PutUint32(buf[0x228:], funcTargetRVA)

	// Names array: 1 entry pointing to function name string
	binary.LittleEndian.PutUint32(buf[0x22C:], funcNameRVA)

	// Ordinals array: 1 entry (ordinal index 0 maps to functions[0])
	binary.LittleEndian.PutUint16(buf[0x230:], 0)

	// "test.dll" string
	copy(buf[0x240:], nameStr)
	buf[0x240+len(nameStr)] = 0

	// Function name string
	copy(buf[0x250:], funcNameStr)
	buf[0x250+len(funcNameStr)] = 0

	return buf
}
