package commands

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"

	"fawkes/pkg/structs"
)

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
			return errorf("Error SRV lookup %s: %v", target, err)
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("[*] SRV records for %s (%d found)\n", target, len(addrs)))
		for _, srv := range addrs {
			sb.WriteString(fmt.Sprintf("  %s:%d (priority=%d, weight=%d)\n", srv.Target, srv.Port, srv.Priority, srv.Weight))
		}
		return successResult(sb.String())
	}

	// Default: query _ldap._tcp for the domain
	service = "ldap"
	proto = "tcp"
	domain = target

	_, addrs, err := r.LookupSRV(ctx, service, proto, domain)
	if err != nil {
		return errorf("Error SRV lookup _%s._%s.%s: %v", service, proto, domain, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] SRV records for _%s._%s.%s (%d found)\n", service, proto, domain, len(addrs)))
	for _, srv := range addrs {
		sb.WriteString(fmt.Sprintf("  %s:%d (priority=%d, weight=%d)\n", srv.Target, srv.Port, srv.Priority, srv.Weight))
	}

	return successResult(sb.String())
}

func dnsMX(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	records, err := r.LookupMX(ctx, args.Target)
	if err != nil {
		return errorf("Error MX lookup %s: %v", args.Target, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] MX records for %s (%d found)\n", args.Target, len(records)))
	for _, mx := range records {
		sb.WriteString(fmt.Sprintf("  %s (preference=%d)\n", mx.Host, mx.Pref))
	}

	return successResult(sb.String())
}

func dnsNS(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	records, err := r.LookupNS(ctx, args.Target)
	if err != nil {
		return errorf("Error NS lookup %s: %v", args.Target, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] NS records for %s (%d found)\n", args.Target, len(records)))
	for _, ns := range records {
		sb.WriteString(fmt.Sprintf("  %s\n", ns.Host))
	}

	return successResult(sb.String())
}

func dnsTXT(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	records, err := r.LookupTXT(ctx, args.Target)
	if err != nil {
		return errorf("Error TXT lookup %s: %v", args.Target, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] TXT records for %s (%d found)\n", args.Target, len(records)))
	for _, txt := range records {
		sb.WriteString(fmt.Sprintf("  \"%s\"\n", txt))
	}

	return successResult(sb.String())
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

	return successResult(sb.String())
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

	return successResult(sb.String())
}

// dnsWildcard detects wildcard DNS by resolving random nonexistent subdomains.
// If random names resolve, the domain has wildcard DNS configured — important
// for filtering false positives during subdomain enumeration.
func dnsWildcard(ctx context.Context, r *net.Resolver, args dnsArgs) structs.CommandResult {
	// Generate 3 random subdomain probes for reliability
	probes := make([]string, 3)
	for i := range probes {
		probes[i] = fmt.Sprintf("fwkprb%08x.%s", rand.Uint32(), args.Target)
	}

	var resolved []string
	var wildcardIPs []string

	for _, probe := range probes {
		addrs, err := r.LookupHost(ctx, probe)
		if err == nil && len(addrs) > 0 {
			resolved = append(resolved, probe)
			wildcardIPs = append(wildcardIPs, addrs...)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Wildcard DNS check for %s\n\n", args.Target))

	if len(resolved) == 0 {
		sb.WriteString("Result: No wildcard detected\n")
		sb.WriteString("Random subdomains did not resolve — subdomain enumeration results are reliable.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Result: WILDCARD DETECTED (%d/%d probes resolved)\n\n", len(resolved), len(probes)))

		// Deduplicate IPs
		seen := make(map[string]bool)
		var unique []string
		for _, ip := range wildcardIPs {
			if !seen[ip] {
				seen[ip] = true
				unique = append(unique, ip)
			}
		}

		sb.WriteString("Wildcard IPs:\n")
		for _, ip := range unique {
			sb.WriteString(fmt.Sprintf("  %s\n", ip))
		}
		sb.WriteString("\nSubdomain enumeration will produce false positives.\n")
		sb.WriteString("Filter results by excluding these IPs.\n")
	}

	return successResult(sb.String())
}
