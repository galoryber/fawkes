package commands

import (
	"testing"
)

func TestExtractXMLValue(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		tag      string
		expected string
	}{
		{
			name:     "simple value",
			xml:      "<Account>123456789012</Account>",
			tag:      "Account",
			expected: "123456789012",
		},
		{
			name:     "nested in response",
			xml:      "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/MyRole/i-1234567890abcdef0</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
			tag:      "Account",
			expected: "123456789012",
		},
		{
			name:     "extract ARN",
			xml:      "<Arn>arn:aws:sts::123456789012:assumed-role/MyRole/i-abc</Arn>",
			tag:      "Arn",
			expected: "arn:aws:sts::123456789012:assumed-role/MyRole/i-abc",
		},
		{
			name:     "tag not found",
			xml:      "<Account>123</Account>",
			tag:      "Arn",
			expected: "",
		},
		{
			name:     "empty xml",
			xml:      "",
			tag:      "Account",
			expected: "",
		},
		{
			name:     "empty value",
			xml:      "<UserId></UserId>",
			tag:      "UserId",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cloudExtractXMLValue(tt.xml, tt.tag)
			if result != tt.expected {
				t.Errorf("cloudExtractXMLValue(%q, %q) = %q, want %q", tt.xml, tt.tag, result, tt.expected)
			}
		})
	}
}

func TestExtractXMLValues(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		tag      string
		expected []string
	}{
		{
			name:     "multiple values",
			xml:      "<member>PolicyA</member><member>PolicyB</member><member>PolicyC</member>",
			tag:      "member",
			expected: []string{"PolicyA", "PolicyB", "PolicyC"},
		},
		{
			name:     "nested in response",
			xml:      "<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>InlinePolicy1</member><member>InlinePolicy2</member></PolicyNames></ListRolePoliciesResult></ListRolePoliciesResponse>",
			tag:      "member",
			expected: []string{"InlinePolicy1", "InlinePolicy2"},
		},
		{
			name:     "policy names and ARNs",
			xml:      "<PolicyName>AdminAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdminAccess</PolicyArn><PolicyName>ReadOnly</PolicyName><PolicyArn>arn:aws:iam::aws:policy/ReadOnly</PolicyArn>",
			tag:      "PolicyName",
			expected: []string{"AdminAccess", "ReadOnly"},
		},
		{
			name:     "no matches",
			xml:      "<Other>value</Other>",
			tag:      "member",
			expected: nil,
		},
		{
			name:     "single value",
			xml:      "<PolicyName>OnlyOne</PolicyName>",
			tag:      "PolicyName",
			expected: []string{"OnlyOne"},
		},
		{
			name:     "empty xml",
			xml:      "",
			tag:      "member",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cloudExtractXMLValues(tt.xml, tt.tag)
			if len(result) != len(tt.expected) {
				t.Errorf("cloudExtractXMLValues(%q, %q) returned %d values, want %d", tt.xml, tt.tag, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("cloudExtractXMLValues[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}
