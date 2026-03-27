//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

func TestParseHive(t *testing.T) {
	tests := []struct {
		input   string
		wantKey registry.Key
		wantErr bool
	}{
		{"HKLM", registry.LOCAL_MACHINE, false},
		{"hklm", registry.LOCAL_MACHINE, false},
		{"HKEY_LOCAL_MACHINE", registry.LOCAL_MACHINE, false},
		{"HKCU", registry.CURRENT_USER, false},
		{"HKEY_CURRENT_USER", registry.CURRENT_USER, false},
		{"HKCR", registry.CLASSES_ROOT, false},
		{"HKEY_CLASSES_ROOT", registry.CLASSES_ROOT, false},
		{"HKU", registry.USERS, false},
		{"HKEY_USERS", registry.USERS, false},
		{"HKCC", registry.CURRENT_CONFIG, false},
		{"HKEY_CURRENT_CONFIG", registry.CURRENT_CONFIG, false},
		{"INVALID", 0, true},
		{"", 0, true},
		{"HKEY_SOMETHING", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			key, err := parseHive(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHive(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && key != tt.wantKey {
				t.Errorf("parseHive(%q) = %v, want %v", tt.input, key, tt.wantKey)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "unsupported registry hive") {
				t.Errorf("parseHive(%q) error = %q, want 'unsupported registry hive'", tt.input, err.Error())
			}
		})
	}
}

func TestRegistryTypeName(t *testing.T) {
	tests := []struct {
		valType uint32
		want    string
	}{
		{registry.SZ, "REG_SZ"},
		{registry.EXPAND_SZ, "REG_EXPAND_SZ"},
		{registry.BINARY, "REG_BINARY"},
		{registry.DWORD, "REG_DWORD"},
		{registry.MULTI_SZ, "REG_MULTI_SZ"},
		{registry.QWORD, "REG_QWORD"},
		{99, "TYPE(99)"},
		{0, "REG_SZ"}, // REG_SZ is 0 in the registry package
	}

	for _, tt := range tests {
		got := registryTypeName(tt.valType)
		if got != tt.want {
			t.Errorf("registryTypeName(%d) = %q, want %q", tt.valType, got, tt.want)
		}
	}
}

func TestReadValueSZ(t *testing.T) {
	testPath := `Software\FawkesTest\ReadValueTest`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	// Write a test string value
	if err := key.SetStringValue("TestStr", "hello world"); err != nil {
		t.Fatalf("Failed to set string value: %v", err)
	}

	output, err := readValue(key, "TestStr")
	if err != nil {
		t.Fatalf("readValue returned error: %v", err)
	}
	if !strings.Contains(output, "hello world") {
		t.Errorf("Expected 'hello world' in output, got: %s", output)
	}
	if !strings.Contains(output, "REG_SZ") {
		t.Errorf("Expected REG_SZ in output, got: %s", output)
	}
}

func TestReadValueDWORD(t *testing.T) {
	testPath := `Software\FawkesTest\ReadValueDWORD`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	if err := key.SetDWordValue("TestDW", 42); err != nil {
		t.Fatalf("Failed to set DWORD value: %v", err)
	}

	output, err := readValue(key, "TestDW")
	if err != nil {
		t.Fatalf("readValue returned error: %v", err)
	}
	if !strings.Contains(output, "42") {
		t.Errorf("Expected '42' in output, got: %s", output)
	}
	if !strings.Contains(output, "REG_DWORD") {
		t.Errorf("Expected REG_DWORD in output, got: %s", output)
	}
}

func TestReadValueBinary(t *testing.T) {
	testPath := `Software\FawkesTest\ReadValueBinary`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	binData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := key.SetBinaryValue("TestBin", binData); err != nil {
		t.Fatalf("Failed to set binary value: %v", err)
	}

	output, err := readValue(key, "TestBin")
	if err != nil {
		t.Fatalf("readValue returned error: %v", err)
	}
	if !strings.Contains(output, "deadbeef") {
		t.Errorf("Expected 'deadbeef' in output, got: %s", output)
	}
	if !strings.Contains(output, "REG_BINARY") {
		t.Errorf("Expected REG_BINARY in output, got: %s", output)
	}
}

func TestParseRegWriteValueSZ(t *testing.T) {
	testPath := `Software\FawkesTest\WriteHelperTest`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	err = parseRegWriteValue(key, "TestSZ", "hello", "REG_SZ")
	if err != nil {
		t.Fatalf("parseRegWriteValue failed: %v", err)
	}

	val, _, err := key.GetStringValue("TestSZ")
	if err != nil {
		t.Fatalf("Failed to read back: %v", err)
	}
	if val != "hello" {
		t.Errorf("Expected 'hello', got '%s'", val)
	}
}

func TestParseRegWriteValueDWORD(t *testing.T) {
	testPath := `Software\FawkesTest\WriteHelperDWORD`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	// Decimal
	err = parseRegWriteValue(key, "TestDW", "123", "REG_DWORD")
	if err != nil {
		t.Fatalf("parseRegWriteValue decimal failed: %v", err)
	}

	// Hex
	err = parseRegWriteValue(key, "TestDWHex", "0xFF", "REG_DWORD")
	if err != nil {
		t.Fatalf("parseRegWriteValue hex failed: %v", err)
	}

	val, _, err := key.GetIntegerValue("TestDWHex")
	if err != nil {
		t.Fatalf("Failed to read back: %v", err)
	}
	if val != 255 {
		t.Errorf("Expected 255, got %d", val)
	}
}

func TestParseRegWriteValueInvalidType(t *testing.T) {
	testPath := `Software\FawkesTest\WriteHelperBadType`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	err = parseRegWriteValue(key, "Test", "data", "REG_INVALID")
	if err == nil {
		t.Error("Expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "unsupported registry type") {
		t.Errorf("Expected unsupported type error, got: %v", err)
	}
}

func TestParseRegWriteValueInvalidDWORD(t *testing.T) {
	testPath := `Software\FawkesTest\WriteHelperBadDW`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	err = parseRegWriteValue(key, "Test", "not_a_number", "REG_DWORD")
	if err == nil {
		t.Error("Expected error for invalid DWORD value")
	}
}

func TestEnumerateValues(t *testing.T) {
	testPath := `Software\FawkesTest\EnumerateTest`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	defer func() {
		key.Close()
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	key.SetStringValue("Name1", "value1")
	key.SetDWordValue("Name2", 42)

	output, err := enumerateValues(key, "HKCU", testPath)
	if err != nil {
		t.Fatalf("enumerateValues returned error: %v", err)
	}
	if !strings.Contains(output, "Name1") {
		t.Errorf("Expected 'Name1' in output, got: %s", output)
	}
	if !strings.Contains(output, "Name2") {
		t.Errorf("Expected 'Name2' in output, got: %s", output)
	}
	if !strings.Contains(output, "value1") {
		t.Errorf("Expected 'value1' in output, got: %s", output)
	}
}

// TestRegCommandActionDispatch tests the unified reg command's action dispatch
func TestRegCommandNoAction(t *testing.T) {
	cmd := &RegCommand{}
	task := structs.Task{Params: "{}"}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success for usage display, got: %s", result.Status)
	}
	if !strings.Contains(result.Output, "Usage:") {
		t.Errorf("Expected usage message, got: %s", result.Output)
	}
}

func TestRegCommandInvalidAction(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(map[string]string{"action": "invalid"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for invalid action, got: %s", result.Status)
	}
}

func TestRegCommandReadAction(t *testing.T) {
	// Create a test key
	testPath := `Software\FawkesTest\RegCmdRead`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	key.SetStringValue("TestVal", "regcmd")
	key.Close()
	defer func() {
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	cmd := &RegCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "read",
		"hive":   "HKCU",
		"path":   testPath,
		"name":   "TestVal",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected completed, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "regcmd") {
		t.Errorf("Expected 'regcmd' in output, got: %s", result.Output)
	}
}

func TestRegCommandWriteAction(t *testing.T) {
	testPath := `Software\FawkesTest\RegCmdWrite`
	defer func() {
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	cmd := &RegCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action":   "write",
		"hive":     "HKCU",
		"path":     testPath,
		"name":     "TestVal",
		"data":     "written",
		"reg_type": "REG_SZ",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected completed, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Successfully wrote") {
		t.Errorf("Expected success confirmation, got: %s", result.Output)
	}

	// Verify
	key, err := registry.OpenKey(registry.CURRENT_USER, testPath, registry.READ)
	if err != nil {
		t.Fatalf("Failed to open key: %v", err)
	}
	val, _, err := key.GetStringValue("TestVal")
	key.Close()
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}
	if val != "written" {
		t.Errorf("Expected 'written', got '%s'", val)
	}
}

func TestRegCommandDeleteAction(t *testing.T) {
	testPath := `Software\FawkesTest\RegCmdDelete`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	key.SetStringValue("Victim", "doomed")
	key.Close()
	defer func() {
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	cmd := &RegCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "delete",
		"hive":   "HKCU",
		"path":   testPath,
		"name":   "Victim",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s — %s", result.Status, result.Output)
	}
}

func TestRegCommandSearchAction(t *testing.T) {
	testPath := `Software\FawkesTest\RegCmdSearch`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	key.SetStringValue("SearchTarget", "findme_unique_12345")
	key.Close()
	defer func() {
		registry.DeleteKey(registry.CURRENT_USER, testPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
	}()

	cmd := &RegCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action":      "search",
		"hive":        "HKCU",
		"path":        `Software\FawkesTest`,
		"pattern":     "findme_unique_12345",
		"max_depth":   3,
		"max_results": 10,
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "findme_unique_12345") {
		t.Errorf("Expected search result with findme_unique_12345, got: %s", result.Output)
	}
}
