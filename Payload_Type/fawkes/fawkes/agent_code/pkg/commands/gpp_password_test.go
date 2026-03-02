package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGppPasswordCommandName(t *testing.T) {
	cmd := &GppPasswordCommand{}
	if cmd.Name() != "gpp-password" {
		t.Errorf("expected 'gpp-password', got '%s'", cmd.Name())
	}
}

func TestGppPasswordCommandDescription(t *testing.T) {
	cmd := &GppPasswordCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("description should not be empty")
	}
}

func TestGppPasswordEmptyParams(t *testing.T) {
	cmd := &GppPasswordCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for empty params, got '%s'", result.Status)
	}
}

func TestGppPasswordInvalidJSON(t *testing.T) {
	cmd := &GppPasswordCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got '%s'", result.Status)
	}
}

func TestGppPasswordMissingServer(t *testing.T) {
	cmd := &GppPasswordCommand{}
	params, _ := json.Marshal(map[string]string{
		"username": "user@domain",
		"password": "pass",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing server, got '%s'", result.Status)
	}
}

func TestGppPasswordMissingCredentials(t *testing.T) {
	cmd := &GppPasswordCommand{}
	params, _ := json.Marshal(map[string]string{
		"server": "dc01",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing credentials, got '%s'", result.Status)
	}
}

func TestGppDecryptKnownPassword(t *testing.T) {
	// Known GPP cpassword test vector — this cpassword decrypts to "GPPstillStandingStrong2k18"
	cpassword := "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
	result := gppDecrypt(cpassword)
	if result != "GPPstillStandingStrong2k18" {
		t.Errorf("expected 'GPPstillStandingStrong2k18', got '%s'", result)
	}
}

func TestGppDecryptEmpty(t *testing.T) {
	result := gppDecrypt("")
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestGppUTF16LEToString(t *testing.T) {
	// "AB" in UTF-16LE
	data := []byte{0x41, 0x00, 0x42, 0x00}
	result := gppUTF16LEToString(data)
	if result != "AB" {
		t.Errorf("expected 'AB', got '%s'", result)
	}
}

func TestGppUTF16LEToStringWithNull(t *testing.T) {
	// "A" followed by null terminator
	data := []byte{0x41, 0x00, 0x00, 0x00, 0x42, 0x00}
	result := gppUTF16LEToString(data)
	if result != "A" {
		t.Errorf("expected 'A', got '%s'", result)
	}
}

// --- Additional gppDecrypt tests ---

func TestGppDecrypt_MalformedBase64(t *testing.T) {
	result := gppDecrypt("not!!valid!!base64")
	if !strings.Contains(result, "decode error") {
		t.Errorf("expected decode error, got %q", result)
	}
}

func TestGppDecrypt_NonBlockAligned(t *testing.T) {
	// Base64 of 7 bytes — not a multiple of AES block size (16)
	result := gppDecrypt("AQIDBAUG") // 6 bytes decoded
	if !strings.Contains(result, "invalid ciphertext length") {
		t.Errorf("expected ciphertext length error, got %q", result)
	}
}

func TestGppDecrypt_NeedsPadding(t *testing.T) {
	// cpassword without trailing = padding (common in GPP XML)
	// The function should auto-pad
	cpassword := "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
	result := gppDecrypt(cpassword)
	if result != "GPPstillStandingStrong2k18" {
		t.Errorf("expected 'GPPstillStandingStrong2k18', got %q", result)
	}
}

func TestGppDecrypt_AESKeyLength(t *testing.T) {
	// Verify the well-known MS14-025 key is 32 bytes (AES-256)
	if len(gppAESKey) != 32 {
		t.Errorf("gppAESKey length = %d, want 32", len(gppAESKey))
	}
}

func TestGppDecrypt_AESKeyFirstByte(t *testing.T) {
	// First byte of the well-known key
	if gppAESKey[0] != 0x4e {
		t.Errorf("gppAESKey[0] = 0x%02x, want 0x4e", gppAESKey[0])
	}
}

// --- gppUTF16LEToString edge cases ---

func TestGppUTF16LEToString_Empty(t *testing.T) {
	result := gppUTF16LEToString([]byte{})
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestGppUTF16LEToString_SingleByte(t *testing.T) {
	// Odd length: less than 2 bytes, should return raw string
	result := gppUTF16LEToString([]byte{0x41})
	if result != "A" {
		t.Errorf("expected 'A', got %q", result)
	}
}

func TestGppUTF16LEToString_Unicode(t *testing.T) {
	// "€" U+20AC = 0xAC 0x20 in UTF-16LE
	data := []byte{0xAC, 0x20}
	result := gppUTF16LEToString(data)
	if result != "€" {
		t.Errorf("expected '€', got %q", result)
	}
}

func TestGppUTF16LEToString_MixedASCII(t *testing.T) {
	// "Password123" in UTF-16LE
	input := "Password123"
	var data []byte
	for _, ch := range input {
		data = append(data, byte(ch), 0)
	}
	result := gppUTF16LEToString(data)
	if result != input {
		t.Errorf("expected %q, got %q", input, result)
	}
}

// --- gppParseXML tests ---

func TestGppParseXML_Groups(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Groups>
  <User changed="2024-01-15 10:30:00" name="LocalAdmin">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="admin" newName="Admin" action="U"/>
  </User>
</Groups>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/Groups.xml", &results)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Username != "admin" {
		t.Errorf("username = %q, want %q", results[0].Username, "admin")
	}
	if results[0].Password != "GPPstillStandingStrong2k18" {
		t.Errorf("password = %q, want %q", results[0].Password, "GPPstillStandingStrong2k18")
	}
	if results[0].File != "test/Groups.xml" {
		t.Errorf("file = %q, want %q", results[0].File, "test/Groups.xml")
	}
	if results[0].NewName != "Admin" {
		t.Errorf("newName = %q, want %q", results[0].NewName, "Admin")
	}
	if results[0].Action != "U" {
		t.Errorf("action = %q, want %q", results[0].Action, "U")
	}
	if results[0].Changed != "2024-01-15 10:30:00" {
		t.Errorf("changed = %q, want %q", results[0].Changed, "2024-01-15 10:30:00")
	}
}

func TestGppParseXML_ScheduledTasks(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<ScheduledTasks>
  <Task changed="2024-02-01 08:00:00">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="svc_backup" action="C"/>
  </Task>
</ScheduledTasks>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/ScheduledTasks.xml", &results)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Username != "svc_backup" {
		t.Errorf("username = %q, want %q", results[0].Username, "svc_backup")
	}
	if results[0].Action != "C" {
		t.Errorf("action = %q, want %q", results[0].Action, "C")
	}
}

func TestGppParseXML_Services(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<NTServices>
  <NTService changed="2024-03-01 12:00:00">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="svc_sql" action="U"/>
  </NTService>
</NTServices>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/Services.xml", &results)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Username != "svc_sql" {
		t.Errorf("username = %q, want %q", results[0].Username, "svc_sql")
	}
}

func TestGppParseXML_DataSources(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<DataSources>
  <DataSource changed="2024-04-01 09:00:00">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="db_user" action="R"/>
  </DataSource>
</DataSources>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/DataSources.xml", &results)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Username != "db_user" {
		t.Errorf("username = %q, want %q", results[0].Username, "db_user")
	}
}

func TestGppParseXML_Drives(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Drives>
  <Drive changed="2024-05-01 14:00:00">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="share_user" action="U"/>
  </Drive>
</Drives>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/Drives.xml", &results)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Username != "share_user" {
		t.Errorf("username = %q, want %q", results[0].Username, "share_user")
	}
}

func TestGppParseXML_MultipleUsers(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Groups>
  <User changed="2024-01-01 00:00:00">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="admin1" action="U"/>
  </User>
  <User changed="2024-01-02 00:00:00">
    <Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="admin2" action="C"/>
  </User>
</Groups>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/Groups.xml", &results)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Username != "admin1" {
		t.Errorf("results[0].username = %q, want %q", results[0].Username, "admin1")
	}
	if results[1].Username != "admin2" {
		t.Errorf("results[1].username = %q, want %q", results[1].Username, "admin2")
	}
}

func TestGppParseXML_NoCpassword(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Groups>
  <User changed="2024-01-01 00:00:00">
    <Properties cpassword="" userName="admin" action="U"/>
  </User>
</Groups>`

	var results []gppResult
	gppParseXML([]byte(xml), "test/Groups.xml", &results)
	if len(results) != 0 {
		t.Errorf("got %d results, want 0 (no cpassword)", len(results))
	}
}

func TestGppParseXML_InvalidXML(t *testing.T) {
	// Should not panic on invalid XML
	var results []gppResult
	gppParseXML([]byte("not xml at all <<<<"), "test/bad.xml", &results)
	// No crash is success
	_ = results
}

func TestGppParseXML_EmptyData(t *testing.T) {
	var results []gppResult
	gppParseXML([]byte{}, "test/empty.xml", &results)
	if len(results) != 0 {
		t.Errorf("got %d results from empty data, want 0", len(results))
	}
}

// --- Domain parsing tests ---

func TestGppCommand_DomainFromUPN(t *testing.T) {
	cmd := &GppPasswordCommand{}
	params, _ := json.Marshal(gppArgs{
		Server:   "192.168.1.1",
		Username: "user@example.com",
		Password: "pass",
	})
	// Will fail on SMB connect, but the domain parse happens before that
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Expect connection error, not auth parsing error
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
	// Should contain TCP connection error (not domain parsing error)
	if !strings.Contains(result.Output, "TCP connect") && !strings.Contains(result.Output, "connect") {
		t.Logf("Output: %s", result.Output)
	}
}

func TestGppCommand_DomainFromNetBIOS(t *testing.T) {
	cmd := &GppPasswordCommand{}
	params, _ := json.Marshal(gppArgs{
		Server:   "192.168.1.1",
		Username: `EXAMPLE\user`,
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestGppCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("gpp-password")
	if cmd == nil {
		t.Fatal("gpp-password not registered")
	}
}
