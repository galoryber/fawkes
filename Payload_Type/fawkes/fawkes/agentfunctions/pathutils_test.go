package agentfunctions

import "testing"

func TestExtractQuotedArg_DoubleQuoted(t *testing.T) {
	arg, rest := extractQuotedArg(`"C:\Program Files\foo.exe" --help`)
	if arg != `C:\Program Files\foo.exe` {
		t.Errorf("arg = %q, want %q", arg, `C:\Program Files\foo.exe`)
	}
	if rest != " --help" {
		t.Errorf("rest = %q, want %q", rest, " --help")
	}
}

func TestExtractQuotedArg_SingleQuoted(t *testing.T) {
	arg, rest := extractQuotedArg(`'/tmp/my file.txt' -v`)
	if arg != "/tmp/my file.txt" {
		t.Errorf("arg = %q, want %q", arg, "/tmp/my file.txt")
	}
	if rest != " -v" {
		t.Errorf("rest = %q, want %q", rest, " -v")
	}
}

func TestExtractQuotedArg_Unquoted(t *testing.T) {
	arg, rest := extractQuotedArg("hello world")
	if arg != "hello" {
		t.Errorf("arg = %q, want %q", arg, "hello")
	}
	if rest != "world" {
		t.Errorf("rest = %q, want %q", rest, "world")
	}
}

func TestExtractQuotedArg_Empty(t *testing.T) {
	arg, rest := extractQuotedArg("")
	if arg != "" {
		t.Errorf("arg = %q, want empty", arg)
	}
	if rest != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

func TestExtractQuotedArg_Whitespace(t *testing.T) {
	arg, rest := extractQuotedArg("   hello")
	if arg != "hello" {
		t.Errorf("arg = %q, want %q", arg, "hello")
	}
	if rest != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

func TestExtractQuotedArg_UnterminatedDouble(t *testing.T) {
	arg, rest := extractQuotedArg(`"unterminated`)
	if arg != "unterminated" {
		t.Errorf("arg = %q, want %q", arg, "unterminated")
	}
	if rest != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

func TestExtractQuotedArg_UnterminatedSingle(t *testing.T) {
	arg, rest := extractQuotedArg("'unterminated")
	if arg != "unterminated" {
		t.Errorf("arg = %q, want %q", arg, "unterminated")
	}
	if rest != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

func TestExtractQuotedArg_EmptyQuoted(t *testing.T) {
	arg, rest := extractQuotedArg(`"" next`)
	if arg != "" {
		t.Errorf("arg = %q, want empty", arg)
	}
	if rest != " next" {
		t.Errorf("rest = %q, want %q", rest, " next")
	}
}

func TestExtractQuotedArg_SingleWord(t *testing.T) {
	arg, rest := extractQuotedArg("command")
	if arg != "command" {
		t.Errorf("arg = %q, want %q", arg, "command")
	}
	if rest != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

func TestExtractQuotedArg_MultipleSpaces(t *testing.T) {
	arg, rest := extractQuotedArg("first   second   third")
	if arg != "first" {
		t.Errorf("arg = %q, want %q", arg, "first")
	}
	// After first space, rest should be the remainder
	if rest != "  second   third" {
		t.Errorf("rest = %q, want %q", rest, "  second   third")
	}
}

func TestExtractQuotedArg_WindowsPath(t *testing.T) {
	arg, rest := extractQuotedArg(`"C:\Users\admin\Desktop\tool.exe" -scan 192.168.1.0/24`)
	if arg != `C:\Users\admin\Desktop\tool.exe` {
		t.Errorf("arg = %q, want %q", arg, `C:\Users\admin\Desktop\tool.exe`)
	}
	if rest != " -scan 192.168.1.0/24" {
		t.Errorf("rest = %q, want %q", rest, " -scan 192.168.1.0/24")
	}
}
