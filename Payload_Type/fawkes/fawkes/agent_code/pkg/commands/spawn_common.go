package commands

type SpawnParams struct {
	Mode      string `json:"mode"`
	Path      string `json:"path"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	BlockDLLs bool   `json:"blockdlls"`
}
