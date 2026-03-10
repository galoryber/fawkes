//go:build !windows

package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripSudoPrompt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no prompt",
			input:    "uid=0(root) gid=0(root)",
			expected: "uid=0(root) gid=0(root)",
		},
		{
			name:     "sudo prompt prefix",
			input:    "[sudo] password for gary: \nuid=0(root) gid=0(root)",
			expected: "uid=0(root) gid=0(root)",
		},
		{
			name:     "Password prompt",
			input:    "Password:\nsome output",
			expected: "some output",
		},
		{
			name:     "sorry message",
			input:    "Sorry, try again.\nPassword:\nmore output",
			expected: "more output",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "only prompt",
			input:    "[sudo] password for user: ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripSudoPrompt(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
