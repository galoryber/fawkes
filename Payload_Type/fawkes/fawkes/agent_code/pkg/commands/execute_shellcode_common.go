package commands

type executeShellcodeArgs struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Technique    string `json:"technique"`
}
