package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type DnsCommand struct{}

func (c *DnsCommand) Name() string        { return "dns" }
func (c *DnsCommand) Description() string { return "DNS enumeration — resolve hosts, query records, discover domain controllers (T1018)" }

type dnsArgs struct {
	Action  string `json:"action"`  // resolve, reverse, srv, mx, ns, txt, cname, all, dc
	Target  string `json:"target"`  // hostname, IP, or domain
	Server  string `json:"server"`  // DNS server (optional)
	Timeout int    `json:"timeout"` // timeout in seconds (default: 5)
}

func (c *DnsCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <resolve|reverse|srv|mx|ns|txt|cname|all|dc> -target <host>",
			Status:    "error",
			Completed: true,
		}
	}

	var args dnsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: target is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		return structs.CommandResult{
			Output:    "Error: action required. Valid: resolve, reverse, srv, mx, ns, txt, cname, all, dc",
			Status:    "error",
			Completed: true,
		}
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
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action %q. Valid: resolve, reverse, srv, mx, ns, txt, cname, all, dc", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func dnsResolve(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	addrs, err := r.LookupHost(ctx, args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving %s: %v", args.Target, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] A/AAAA records for %s (%d found)\n", args.Target, len(addrs)))
	for _, addr := range addrs {
		sb.WriteString(fmt.Sprintf("  %s\n", addr))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsReverse(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	names, err := r.LookupAddr(ctx, args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reverse lookup %s: %v", args.Target, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] PTR records for %s (%d found)\n", args.Target, len(names)))
	for _, name := range names {
		sb.WriteString(fmt.Sprintf("  %s\n", name))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsSRV(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	// If target looks like a full SRV name (starts with _), query directly
	// Otherwise, assume it's a domain and query _ldap._tcp
	target := args.Target
	service := ""
	proto := ""
	domain := ""

	if strings.HasPrefix(target, "_") {
		// Full SRV record like _ldap._tcp.domain.local
		_, addrs, err := r.LookupSRV(ctx, "", "", target)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error SRV lookup %s: %v", target, err),
				Status:    "error",
				Completed: true,
			}
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("[*] SRV records for %s (%d found)\n", target, len(addrs)))
		for _, srv := range addrs {
			sb.WriteString(fmt.Sprintf("  %s:%d (priority=%d, weight=%d)\n", srv.Target, srv.Port, srv.Priority, srv.Weight))
		}
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "success",
			Completed: true,
		}
	}

	// Default: query _ldap._tcp for the domain
	service = "ldap"
	proto = "tcp"
	domain = target

	_, addrs, err := r.LookupSRV(ctx, service, proto, domain)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error SRV lookup _%s._%s.%s: %v", service, proto, domain, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] SRV records for _%s._%s.%s (%d found)\n", service, proto, domain, len(addrs)))
	for _, srv := range addrs {
		sb.WriteString(fmt.Sprintf("  %s:%d (priority=%d, weight=%d)\n", srv.Target, srv.Port, srv.Priority, srv.Weight))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsMX(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	records, err := r.LookupMX(ctx, args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error MX lookup %s: %v", args.Target, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] MX records for %s (%d found)\n", args.Target, len(records)))
	for _, mx := range records {
		sb.WriteString(fmt.Sprintf("  %s (preference=%d)\n", mx.Host, mx.Pref))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsNS(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	records, err := r.LookupNS(ctx, args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error NS lookup %s: %v", args.Target, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] NS records for %s (%d found)\n", args.Target, len(records)))
	for _, ns := range records {
		sb.WriteString(fmt.Sprintf("  %s\n", ns.Host))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsTXT(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	records, err := r.LookupTXT(ctx, args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error TXT lookup %s: %v", args.Target, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] TXT records for %s (%d found)\n", args.Target, len(records)))
	for _, txt := range records {
		sb.WriteString(fmt.Sprintf("  \"%s\"\n", txt))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsCNAME(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	cname, err := r.LookupCNAME(ctx, args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error CNAME lookup %s: %v", args.Target, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[*] CNAME for %s\n  %s\n", args.Target, cname),
		Status:    "success",
		Completed: true,
	}
}

func dnsAll(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] All DNS records for %s\n", args.Target))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	// A/AAAA
	if addrs, err := r.LookupHost(ctx, args.Target); err == nil {
		sb.WriteString(fmt.Sprintf("\n[A/AAAA] %d records\n", len(addrs)))
		for _, addr := range addrs {
			sb.WriteString(fmt.Sprintf("  %s\n", addr))
		}
	}

	// CNAME
	if cname, err := r.LookupCNAME(ctx, args.Target); err == nil && cname != args.Target+"." {
		sb.WriteString(fmt.Sprintf("\n[CNAME]\n  %s\n", cname))
	}

	// MX
	if mxs, err := r.LookupMX(ctx, args.Target); err == nil && len(mxs) > 0 {
		sb.WriteString(fmt.Sprintf("\n[MX] %d records\n", len(mxs)))
		for _, mx := range mxs {
			sb.WriteString(fmt.Sprintf("  %s (preference=%d)\n", mx.Host, mx.Pref))
		}
	}

	// NS
	if nss, err := r.LookupNS(ctx, args.Target); err == nil && len(nss) > 0 {
		sb.WriteString(fmt.Sprintf("\n[NS] %d records\n", len(nss)))
		for _, ns := range nss {
			sb.WriteString(fmt.Sprintf("  %s\n", ns.Host))
		}
	}

	// TXT
	if txts, err := r.LookupTXT(ctx, args.Target); err == nil && len(txts) > 0 {
		sb.WriteString(fmt.Sprintf("\n[TXT] %d records\n", len(txts)))
		for _, txt := range txts {
			sb.WriteString(fmt.Sprintf("  \"%s\"\n", txt))
		}
	}

	// SRV (_ldap._tcp)
	if _, srvs, err := r.LookupSRV(ctx, "ldap", "tcp", args.Target); err == nil && len(srvs) > 0 {
		sb.WriteString(fmt.Sprintf("\n[SRV _ldap._tcp] %d records\n", len(srvs)))
		for _, srv := range srvs {
			sb.WriteString(fmt.Sprintf("  %s:%d\n", srv.Target, srv.Port))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dnsDC(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	domain := args.Target
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Domain Controller discovery for %s\n", domain))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	// SRV records for DC discovery
	srvQueries := []struct {
		service string
		proto   string
		label   string
	}{
		{"ldap", "tcp", "LDAP (Domain Controllers)"},
		{"kerberos", "tcp", "Kerberos (KDC)"},
		{"kpasswd", "tcp", "Kerberos Password Change"},
		{"gc", "tcp", "Global Catalog"},
	}

	for _, q := range srvQueries {
		_, addrs, err := r.LookupSRV(ctx, q.service, q.proto, domain)
		if err != nil {
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n[%s] %d found\n", q.label, len(addrs)))
		for _, srv := range addrs {
			// Resolve the SRV target to IP
			ips, err := r.LookupHost(ctx, strings.TrimSuffix(srv.Target, "."))
			ipStr := ""
			if err == nil && len(ips) > 0 {
				ipStr = fmt.Sprintf(" → %s", ips[0])
			}
			sb.WriteString(fmt.Sprintf("  %s:%d%s\n", srv.Target, srv.Port, ipStr))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
