package commands

import (
	"strings"
	"testing"
)

// --- macBuildPlist tests ---

func TestMacBuildPlist_BasicAgent(t *testing.T) {
	plist := macBuildPlist("com.apple.security.updater", []string{"/usr/local/bin/agent"}, "", 0)

	// Check XML header
	if !strings.HasPrefix(plist, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Error("expected XML header")
	}

	// Check label
	if !strings.Contains(plist, "<string>com.apple.security.updater</string>") {
		t.Error("expected label in plist")
	}

	// Check program arguments
	if !strings.Contains(plist, "<string>/usr/local/bin/agent</string>") {
		t.Error("expected program path in ProgramArguments")
	}

	// Check RunAtLoad
	if !strings.Contains(plist, "<key>RunAtLoad</key>") {
		t.Error("expected RunAtLoad key")
	}

	// Check KeepAlive
	if !strings.Contains(plist, "<key>KeepAlive</key>") {
		t.Error("expected KeepAlive key")
	}

	// Check output suppression
	if !strings.Contains(plist, "<string>/dev/null</string>") {
		t.Error("expected /dev/null for output suppression")
	}

	// Should NOT have StartInterval without interval
	if strings.Contains(plist, "StartInterval") {
		t.Error("should not have StartInterval when interval=0")
	}

	// Should NOT have StartCalendarInterval without runAt
	if strings.Contains(plist, "StartCalendarInterval") {
		t.Error("should not have StartCalendarInterval when runAt is empty")
	}
}

func TestMacBuildPlist_WithInterval(t *testing.T) {
	plist := macBuildPlist("com.test.timer", []string{"/tmp/agent"}, "", 300)

	if !strings.Contains(plist, "<key>StartInterval</key>") {
		t.Error("expected StartInterval key")
	}
	if !strings.Contains(plist, "<integer>300</integer>") {
		t.Error("expected interval value 300")
	}
}

func TestMacBuildPlist_WithCalendar(t *testing.T) {
	plist := macBuildPlist("com.test.cron", []string{"/tmp/agent"}, "09:30", 0)

	if !strings.Contains(plist, "<key>StartCalendarInterval</key>") {
		t.Error("expected StartCalendarInterval key")
	}
	if !strings.Contains(plist, "<key>Hour</key>") {
		t.Error("expected Hour key")
	}
	if !strings.Contains(plist, "<integer>09</integer>") {
		t.Error("expected hour value 09")
	}
	if !strings.Contains(plist, "<key>Minute</key>") {
		t.Error("expected Minute key")
	}
	if !strings.Contains(plist, "<integer>30</integer>") {
		t.Error("expected minute value 30")
	}
}

func TestMacBuildPlist_WithWeekdayCalendar(t *testing.T) {
	plist := macBuildPlist("com.test.weekly", []string{"/tmp/agent"}, "1 09:00", 0)

	if !strings.Contains(plist, "<key>Weekday</key>") {
		t.Error("expected Weekday key")
	}
	if !strings.Contains(plist, "<integer>1</integer>") {
		t.Error("expected weekday value 1 (Monday)")
	}
	if !strings.Contains(plist, "<key>Hour</key>") {
		t.Error("expected Hour key")
	}
	if !strings.Contains(plist, "<key>Minute</key>") {
		t.Error("expected Minute key")
	}
}

func TestMacBuildPlist_MultipleArgs(t *testing.T) {
	plist := macBuildPlist("com.test.multi", []string{"/usr/bin/python3", "-c", "import os"}, "", 0)

	if !strings.Contains(plist, "<string>/usr/bin/python3</string>") {
		t.Error("expected python3 in args")
	}
	if !strings.Contains(plist, "<string>-c</string>") {
		t.Error("expected -c in args")
	}
	if !strings.Contains(plist, "<string>import os</string>") {
		t.Error("expected 'import os' in args")
	}
}

func TestMacBuildPlist_XmlEscapedArgs(t *testing.T) {
	plist := macBuildPlist("com.test.escape", []string{"/bin/sh", "-c", "echo <hello> & world"}, "", 0)

	if !strings.Contains(plist, "&amp;") {
		t.Error("expected & to be escaped as &amp;")
	}
	if !strings.Contains(plist, "&lt;hello&gt;") {
		t.Error("expected < and > to be escaped")
	}
}

func TestMacBuildPlist_WellFormedXml(t *testing.T) {
	plist := macBuildPlist("com.test.valid", []string{"/tmp/agent"}, "", 0)

	if !strings.Contains(plist, "</plist>") {
		t.Error("expected closing </plist> tag")
	}
	if !strings.Contains(plist, "</dict>") {
		t.Error("expected closing </dict> tag")
	}
	if !strings.Contains(plist, "</array>") {
		t.Error("expected closing </array> tag")
	}
}

// --- macXmlEscape tests ---

func TestMacXmlEscape_Ampersand(t *testing.T) {
	result := macXmlEscape("a & b")
	if result != "a &amp; b" {
		t.Errorf("expected 'a &amp; b', got %q", result)
	}
}

func TestMacXmlEscape_LessThan(t *testing.T) {
	result := macXmlEscape("a < b")
	if result != "a &lt; b" {
		t.Errorf("expected 'a &lt; b', got %q", result)
	}
}

func TestMacXmlEscape_GreaterThan(t *testing.T) {
	result := macXmlEscape("a > b")
	if result != "a &gt; b" {
		t.Errorf("expected 'a &gt; b', got %q", result)
	}
}

func TestMacXmlEscape_Quote(t *testing.T) {
	result := macXmlEscape(`say "hello"`)
	if result != "say &quot;hello&quot;" {
		t.Errorf("expected quotes escaped, got %q", result)
	}
}

func TestMacXmlEscape_AllSpecialChars(t *testing.T) {
	result := macXmlEscape(`<script>"alert('xss')" & true</script>`)
	if strings.Contains(result, "<") || strings.Contains(result, ">") {
		t.Error("< and > should be escaped")
	}
	if strings.ContainsRune(result, '"') {
		t.Error("quotes should be escaped")
	}
}

func TestMacXmlEscape_NoSpecialChars(t *testing.T) {
	result := macXmlEscape("hello world 123")
	if result != "hello world 123" {
		t.Errorf("expected unchanged string, got %q", result)
	}
}

func TestMacXmlEscape_EmptyString(t *testing.T) {
	result := macXmlEscape("")
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

// --- macBuildCalendarInterval tests ---

func TestMacBuildCalendarInterval_DailyTime(t *testing.T) {
	result := macBuildCalendarInterval("14:30")
	if !strings.Contains(result, "<key>Hour</key>") {
		t.Error("expected Hour key")
	}
	if !strings.Contains(result, "<integer>14</integer>") {
		t.Error("expected hour 14")
	}
	if !strings.Contains(result, "<integer>30</integer>") {
		t.Error("expected minute 30")
	}
	if strings.Contains(result, "Weekday") {
		t.Error("should not have Weekday for daily schedule")
	}
}

func TestMacBuildCalendarInterval_WeekdayTime(t *testing.T) {
	result := macBuildCalendarInterval("5 17:45")
	if !strings.Contains(result, "<key>Weekday</key>") {
		t.Error("expected Weekday key")
	}
	if !strings.Contains(result, "<integer>5</integer>") {
		t.Error("expected weekday 5 (Friday)")
	}
	if !strings.Contains(result, "<integer>17</integer>") {
		t.Error("expected hour 17")
	}
	if !strings.Contains(result, "<integer>45</integer>") {
		t.Error("expected minute 45")
	}
}

func TestMacBuildCalendarInterval_Midnight(t *testing.T) {
	result := macBuildCalendarInterval("00:00")
	if !strings.Contains(result, "<integer>00</integer>") {
		t.Error("expected hour/minute 00")
	}
}

func TestMacBuildCalendarInterval_HasDictWrapper(t *testing.T) {
	result := macBuildCalendarInterval("12:00")
	if !strings.Contains(result, "<key>StartCalendarInterval</key>") {
		t.Error("expected StartCalendarInterval key")
	}
	if !strings.Contains(result, "<dict>") {
		t.Error("expected opening dict tag")
	}
	if !strings.Contains(result, "</dict>") {
		t.Error("expected closing dict tag")
	}
}

// --- macBuildFilterArgs tests ---

func TestMacBuildFilterArgs_AllFields(t *testing.T) {
	args := macBuildFilterArgs("github.com", "user@example.com", "GitHub Token")
	if len(args) != 6 {
		t.Fatalf("expected 6 args, got %d: %v", len(args), args)
	}
	if args[0] != "-s" || args[1] != "github.com" {
		t.Errorf("expected -s github.com, got %s %s", args[0], args[1])
	}
	if args[2] != "-a" || args[3] != "user@example.com" {
		t.Errorf("expected -a user@example.com, got %s %s", args[2], args[3])
	}
	if args[4] != "-l" || args[5] != "GitHub Token" {
		t.Errorf("expected -l 'GitHub Token', got %s %s", args[4], args[5])
	}
}

func TestMacBuildFilterArgs_ServerOnly(t *testing.T) {
	args := macBuildFilterArgs("imap.gmail.com", "", "")
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
	if args[0] != "-s" || args[1] != "imap.gmail.com" {
		t.Errorf("expected -s imap.gmail.com, got %v", args)
	}
}

func TestMacBuildFilterArgs_AccountOnly(t *testing.T) {
	args := macBuildFilterArgs("", "admin", "")
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
	if args[0] != "-a" || args[1] != "admin" {
		t.Errorf("expected -a admin, got %v", args)
	}
}

func TestMacBuildFilterArgs_LabelOnly(t *testing.T) {
	args := macBuildFilterArgs("", "", "Wi-Fi Password")
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
	if args[0] != "-l" || args[1] != "Wi-Fi Password" {
		t.Errorf("expected -l 'Wi-Fi Password', got %v", args)
	}
}

func TestMacBuildFilterArgs_NoFields(t *testing.T) {
	args := macBuildFilterArgs("", "", "")
	if args != nil {
		t.Errorf("expected nil for no fields, got %v", args)
	}
}

// --- macIsItemNotFound tests ---

func TestMacIsItemNotFound_CouldNotBeFound(t *testing.T) {
	if !macIsItemNotFound("The specified item could not be found in the keychain.") {
		t.Error("expected true for 'could not be found'")
	}
}

func TestMacIsItemNotFound_SecKeychainSearch(t *testing.T) {
	if !macIsItemNotFound("security: SecKeychainSearchCopyNext: The specified item could not be found.") {
		t.Error("expected true for SecKeychainSearchCopyNext")
	}
}

func TestMacIsItemNotFound_FoundItem(t *testing.T) {
	if macIsItemNotFound("class: \"genp\"\n  \"svce\"<blob>=\"Wi-Fi\"") {
		t.Error("expected false for found item output")
	}
}

func TestMacIsItemNotFound_EmptyOutput(t *testing.T) {
	if macIsItemNotFound("") {
		t.Error("expected false for empty output")
	}
}

// --- macTCCServiceFlag tests ---

func TestMacTCCServiceFlag_Accessibility(t *testing.T) {
	flag := macTCCServiceFlag("kTCCServiceAccessibility")
	if !strings.Contains(flag, "Accessibility") {
		t.Errorf("expected Accessibility flag, got %q", flag)
	}
	if !strings.Contains(flag, "[!]") {
		t.Error("expected [!] prefix for high-value permission")
	}
}

func TestMacTCCServiceFlag_ScreenCapture(t *testing.T) {
	flag := macTCCServiceFlag("kTCCServiceScreenCapture")
	if !strings.Contains(flag, "Screen Capture") {
		t.Errorf("expected Screen Capture flag, got %q", flag)
	}
}

func TestMacTCCServiceFlag_FullDiskAccess(t *testing.T) {
	flag := macTCCServiceFlag("kTCCServiceSystemPolicyAllFiles")
	if !strings.Contains(flag, "Full Disk Access") {
		t.Errorf("expected Full Disk Access flag, got %q", flag)
	}
}

func TestMacTCCServiceFlag_Microphone(t *testing.T) {
	flag := macTCCServiceFlag("kTCCServiceMicrophone")
	if !strings.Contains(flag, "Microphone") {
		t.Errorf("expected Microphone flag, got %q", flag)
	}
}

func TestMacTCCServiceFlag_Camera(t *testing.T) {
	flag := macTCCServiceFlag("kTCCServiceCamera")
	if !strings.Contains(flag, "Camera") {
		t.Errorf("expected Camera flag, got %q", flag)
	}
}

func TestMacTCCServiceFlag_UnknownService(t *testing.T) {
	flag := macTCCServiceFlag("kTCCServiceAddressBook")
	if flag != "" {
		t.Errorf("expected empty flag for non-critical service, got %q", flag)
	}
}

func TestMacTCCServiceFlag_EmptyService(t *testing.T) {
	flag := macTCCServiceFlag("")
	if flag != "" {
		t.Errorf("expected empty flag for empty service, got %q", flag)
	}
}
