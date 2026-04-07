//go:build linux || darwin

package commands

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

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
		return fmt.Errorf("reading octet string length: %w", err)
	}
	if length > 1048576 {
		return fmt.Errorf("octet string too long: %d", length)
	}
	if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
		return fmt.Errorf("skipping octet string data (%d bytes): %w", length, err)
	}
	return nil
}
