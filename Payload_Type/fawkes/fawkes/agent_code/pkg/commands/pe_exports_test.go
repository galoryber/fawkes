package commands

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

func TestFindSectionByRVA_EmptySections(t *testing.T) {
	peFile := &pe.File{Sections: nil}
	if s := findSectionByRVA(peFile, 0x1000); s != nil {
		t.Error("findSectionByRVA with no sections should return nil")
	}
}

func TestRvaToOffset_ThreeSections(t *testing.T) {
	peFile := &pe.File{
		Sections: []*pe.Section{
			{SectionHeader: pe.SectionHeader{
				VirtualAddress: 0x1000, VirtualSize: 0x1000, Offset: 0x400,
			}},
			{SectionHeader: pe.SectionHeader{
				VirtualAddress: 0x2000, VirtualSize: 0x1000, Offset: 0x1400,
			}},
			{SectionHeader: pe.SectionHeader{
				VirtualAddress: 0x3000, VirtualSize: 0x2000, Offset: 0x2400,
			}},
		},
	}

	tests := []struct {
		rva  uint32
		want int64
	}{
		{0x1000, 0x400},
		{0x1500, 0x900},
		{0x2000, 0x1400},
		{0x2800, 0x1C00},
		{0x3000, 0x2400},
		{0x4FFF, 0x2400 + 0x1FFF},
	}
	for _, tc := range tests {
		got := rvaToOffset(peFile, tc.rva)
		if got != tc.want {
			t.Errorf("rvaToOffset(0x%x) = 0x%x, want 0x%x", tc.rva, got, tc.want)
		}
	}
}

func TestRvaToOffset_BelowSections(t *testing.T) {
	peFile := &pe.File{
		Sections: []*pe.Section{
			{SectionHeader: pe.SectionHeader{
				VirtualAddress: 0x1000, VirtualSize: 0x1000, Offset: 0x200,
			}},
		},
	}
	if got := rvaToOffset(peFile, 0x500); got != -1 {
		t.Errorf("rvaToOffset(0x500) below .text = %d, want -1", got)
	}
}

func TestFindSectionByRVA_BoundaryEdgeCases(t *testing.T) {
	peFile := &pe.File{
		Sections: []*pe.Section{
			{SectionHeader: pe.SectionHeader{Name: ".text", VirtualAddress: 0x1000, VirtualSize: 0x100}},
			{SectionHeader: pe.SectionHeader{Name: ".data", VirtualAddress: 0x2000, VirtualSize: 0x100}},
		},
	}

	// Just before .text
	if s := findSectionByRVA(peFile, 0x0FFF); s != nil {
		t.Errorf("RVA 0x0FFF should not match, got %q", s.Name)
	}

	// Exact end of .text (VirtualAddress + VirtualSize = 0x1100, so 0x10FF is last valid)
	if s := findSectionByRVA(peFile, 0x10FF); s == nil || s.Name != ".text" {
		t.Error("RVA 0x10FF should match .text")
	}

	// Beyond .text
	if s := findSectionByRVA(peFile, 0x1100); s != nil {
		t.Errorf("RVA 0x1100 should be in gap, got %q", s.Name)
	}

	// Gap between sections
	if s := findSectionByRVA(peFile, 0x1500); s != nil {
		t.Errorf("RVA 0x1500 in gap should return nil, got %q", s.Name)
	}
}

// buildSyntheticPEExport creates minimal PE section data containing an export directory.
func buildSyntheticPEExport(dllName string, exports []string) ([]byte, uint32) {
	numFuncs := uint32(len(exports))
	numNames := numFuncs

	dllNameOff := uint32(40)
	dllNameEnd := dllNameOff + uint32(len(dllName)) + 1

	functionsOff := dllNameEnd
	if functionsOff%4 != 0 {
		functionsOff += 4 - (functionsOff % 4)
	}
	namesOff := functionsOff + numFuncs*4
	ordinalsOff := namesOff + numNames*4
	stringsOff := ordinalsOff + numNames*2
	if stringsOff%2 != 0 {
		stringsOff++
	}

	totalStringSize := uint32(0)
	for _, name := range exports {
		totalStringSize += uint32(len(name)) + 1
	}
	totalSize := stringsOff + totalStringSize
	data := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(data[12:16], dllNameOff)
	binary.LittleEndian.PutUint32(data[16:20], 1) // OrdinalBase
	binary.LittleEndian.PutUint32(data[20:24], numFuncs)
	binary.LittleEndian.PutUint32(data[24:28], numNames)
	binary.LittleEndian.PutUint32(data[28:32], functionsOff)
	binary.LittleEndian.PutUint32(data[32:36], namesOff)
	binary.LittleEndian.PutUint32(data[36:40], ordinalsOff)

	copy(data[dllNameOff:], dllName)

	for i := uint32(0); i < numFuncs; i++ {
		binary.LittleEndian.PutUint32(data[functionsOff+i*4:], 0x10000+i*0x100)
	}

	strOff := stringsOff
	for i := uint32(0); i < numNames; i++ {
		binary.LittleEndian.PutUint32(data[namesOff+i*4:], strOff)
		copy(data[strOff:], exports[i])
		strOff += uint32(len(exports[i])) + 1
	}

	for i := uint32(0); i < numNames; i++ {
		binary.LittleEndian.PutUint16(data[ordinalsOff+i*2:], uint16(i))
	}

	return data, totalSize
}

func TestSyntheticPEExport_StructureIntegrity(t *testing.T) {
	data, size := buildSyntheticPEExport("test.dll", []string{"Alpha", "Beta", "Gamma"})
	if uint32(len(data)) != size {
		t.Fatalf("data length %d != reported size %d", len(data), size)
	}

	numFuncs := binary.LittleEndian.Uint32(data[20:24])
	numNames := binary.LittleEndian.Uint32(data[24:28])
	if numFuncs != 3 || numNames != 3 {
		t.Errorf("numFuncs=%d numNames=%d, want 3,3", numFuncs, numNames)
	}

	// Verify ordinal base
	ordBase := binary.LittleEndian.Uint32(data[16:20])
	if ordBase != 1 {
		t.Errorf("ordinal base = %d, want 1", ordBase)
	}

	// Verify DLL name
	nameRVA := binary.LittleEndian.Uint32(data[12:16])
	end := nameRVA
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}
	if string(data[nameRVA:end]) != "test.dll" {
		t.Errorf("DLL name = %q, want %q", string(data[nameRVA:end]), "test.dll")
	}

	// Verify export name strings via name table
	namesRVA := binary.LittleEndian.Uint32(data[32:36])
	readStr := func(off uint32) string {
		e := off
		for e < uint32(len(data)) && data[e] != 0 {
			e++
		}
		return string(data[off:e])
	}

	expected := []string{"Alpha", "Beta", "Gamma"}
	for i, want := range expected {
		nameOff := binary.LittleEndian.Uint32(data[namesRVA+uint32(i)*4:])
		got := readStr(nameOff)
		if got != want {
			t.Errorf("export[%d] = %q, want %q", i, got, want)
		}
	}
}
