package commands

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
)

type peExport struct {
	ordinal   uint32
	name      string
	forwarder string
}

func peTypeStr(isDLL bool) string {
	if isDLL {
		return "DLL"
	}
	return "EXE"
}

func parseExportDirectory(peFile *pe.File, exportDir pe.DataDirectory) ([]peExport, string, error) {
	sect := findSectionByRVA(peFile, exportDir.VirtualAddress)
	if sect == nil {
		return nil, "", fmt.Errorf("no section contains export directory RVA 0x%x", exportDir.VirtualAddress)
	}

	data, err := sect.Data()
	if err != nil {
		return nil, "", fmt.Errorf("reading section data: %v", err)
	}

	offset := exportDir.VirtualAddress - sect.VirtualAddress
	if uint32(len(data)) < offset+40 {
		return nil, "", fmt.Errorf("export directory truncated")
	}
	dirData := data[offset:]

	numFunctions := binary.LittleEndian.Uint32(dirData[20:24])
	numNames := binary.LittleEndian.Uint32(dirData[24:28])
	addrOfFunctions := binary.LittleEndian.Uint32(dirData[28:32])
	addrOfNames := binary.LittleEndian.Uint32(dirData[32:36])
	addrOfOrdinals := binary.LittleEndian.Uint32(dirData[36:40])
	ordinalBase := binary.LittleEndian.Uint32(dirData[16:20])
	nameRVA := binary.LittleEndian.Uint32(dirData[12:16])

	var dllName string
	if nameRVA > 0 {
		dllName = readPEString(peFile, nameRVA)
	}

	nameMap := make(map[uint32]string)
	for i := uint32(0); i < numNames; i++ {
		nameOff := rvaToOffset(peFile, addrOfNames+i*4)
		ordOff := rvaToOffset(peFile, addrOfOrdinals+i*2)
		if nameOff < 0 || ordOff < 0 {
			continue
		}
		nameRVAEntry := readUint32At(peFile, nameOff)
		ordIndex := readUint16At(peFile, ordOff)
		name := readPEString(peFile, nameRVAEntry)
		nameMap[uint32(ordIndex)] = name
	}

	var exports []peExport
	exportDirStart := exportDir.VirtualAddress
	exportDirEnd := exportDir.VirtualAddress + exportDir.Size

	for i := uint32(0); i < numFunctions; i++ {
		funcOff := rvaToOffset(peFile, addrOfFunctions+i*4)
		if funcOff < 0 {
			continue
		}
		funcRVA := readUint32At(peFile, funcOff)
		if funcRVA == 0 {
			continue
		}

		exp := peExport{
			ordinal: ordinalBase + i,
			name:    nameMap[i],
		}

		if funcRVA >= exportDirStart && funcRVA < exportDirEnd {
			exp.forwarder = readPEString(peFile, funcRVA)
		}

		exports = append(exports, exp)
	}

	return exports, dllName, nil
}

func findSectionByRVA(peFile *pe.File, rva uint32) *pe.Section {
	for _, s := range peFile.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s
		}
	}
	return nil
}

func rvaToOffset(peFile *pe.File, rva uint32) int64 {
	for _, s := range peFile.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return int64(rva - s.VirtualAddress + s.Offset)
		}
	}
	return -1
}

func readUint32At(peFile *pe.File, fileOffset int64) uint32 {
	for _, s := range peFile.Sections {
		start := int64(s.Offset)
		end := start + int64(s.Size)
		if fileOffset >= start && fileOffset < end {
			data, err := s.Data()
			if err != nil {
				return 0
			}
			localOff := fileOffset - start
			if localOff+4 > int64(len(data)) {
				return 0
			}
			return binary.LittleEndian.Uint32(data[localOff : localOff+4])
		}
	}
	return 0
}

func readUint16At(peFile *pe.File, fileOffset int64) uint16 {
	for _, s := range peFile.Sections {
		start := int64(s.Offset)
		end := start + int64(s.Size)
		if fileOffset >= start && fileOffset < end {
			data, err := s.Data()
			if err != nil {
				return 0
			}
			localOff := fileOffset - start
			if localOff+2 > int64(len(data)) {
				return 0
			}
			return binary.LittleEndian.Uint16(data[localOff : localOff+2])
		}
	}
	return 0
}

func readPEString(peFile *pe.File, rva uint32) string {
	fileOff := rvaToOffset(peFile, rva)
	if fileOff < 0 {
		return ""
	}
	for _, s := range peFile.Sections {
		start := int64(s.Offset)
		end := start + int64(s.Size)
		if fileOff >= start && fileOff < end {
			data, err := s.Data()
			if err != nil {
				return ""
			}
			localOff := int(fileOff - start)
			var result strings.Builder
			for i := localOff; i < len(data); i++ {
				if data[i] == 0 {
					break
				}
				result.WriteByte(data[i])
			}
			return result.String()
		}
	}
	return ""
}
