package commands

type runasArgs struct {
	Command  string `json:"command"`  // command to run (e.g. "/bin/sh -c whoami")
	Username string `json:"username"` // target username
	Password string `json:"password"` // target password
	Domain   string `json:"domain"`   // domain (Windows only, ignored on Unix)
	NetOnly  bool   `json:"netonly"`  // LOGON_NETCREDENTIALS_ONLY (Windows only)
}
