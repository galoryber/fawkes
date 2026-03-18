//go:build darwin

package commands

import (
	"testing"
)

func TestParseDsclOutput(t *testing.T) {
	input := `AppleMetaNodeLocation: /Local/Default
GeneratedUID: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
NFSHomeDirectory: /Users/testuser
PrimaryGroupID: 20
RealName:
 Test User
RecordName: testuser
RecordType: dsRecTypeStandard:Users
UniqueID: 501
UserShell: /bin/zsh
AuthenticationAuthority:
 ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>
`

	props := parseDsclOutput(input)

	tests := []struct {
		key      string
		expected string
	}{
		{"AppleMetaNodeLocation", "/Local/Default"},
		{"UniqueID", "501"},
		{"PrimaryGroupID", "20"},
		{"NFSHomeDirectory", "/Users/testuser"},
		{"UserShell", "/bin/zsh"},
		{"RecordName", "testuser"},
		{"RealName", "Test User"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := props[tt.key]
			if got != tt.expected {
				t.Errorf("parseDsclOutput[%q] = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}

	// AuthenticationAuthority should contain ShadowHash
	if auth, ok := props["AuthenticationAuthority"]; !ok {
		t.Error("missing AuthenticationAuthority")
	} else if auth == "" {
		t.Error("AuthenticationAuthority is empty")
	}
}

func TestParseDsclOutput_Empty(t *testing.T) {
	props := parseDsclOutput("")
	if len(props) != 0 {
		t.Errorf("expected empty map for empty input, got %d entries", len(props))
	}
}

func TestParseDsclOutput_SingleLine(t *testing.T) {
	props := parseDsclOutput("UniqueID: 501")
	if props["UniqueID"] != "501" {
		t.Errorf("got %q", props["UniqueID"])
	}
}
