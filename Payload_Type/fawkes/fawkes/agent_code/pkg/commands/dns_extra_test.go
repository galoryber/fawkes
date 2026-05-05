package commands

import (
	"context"
	"net"
	"testing"
)

// TestDNSResolveError covers the dnsResolve error path (line 100-102) using a
// cancelled context so the DNS lookup fails immediately.
func TestDNSResolveError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	r := &net.Resolver{}
	result := dnsResolve(ctx, r, dnsArgs{Target: "example.com"})
	if result.Status != "error" {
		t.Errorf("expected error with cancelled context, got %q: %s", result.Status, result.Output)
	}
}

// TestDNSReverseError covers the dnsReverse error path (line 115-117) using a
// cancelled context so the reverse lookup fails immediately.
func TestDNSReverseError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &net.Resolver{}
	result := dnsReverse(ctx, r, dnsArgs{Target: "8.8.8.8"})
	if result.Status != "error" {
		t.Errorf("expected error with cancelled context, got %q: %s", result.Status, result.Output)
	}
}

// TestDNSCNAMEError covers the dnsCNAME error path (line 130-132) using a
// cancelled context so the CNAME lookup fails immediately.
func TestDNSCNAMEError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &net.Resolver{}
	result := dnsCNAME(ctx, r, dnsArgs{Target: "www.example.com"})
	if result.Status != "error" {
		t.Errorf("expected error with cancelled context, got %q: %s", result.Status, result.Output)
	}
}
