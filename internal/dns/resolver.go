package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Resolver performs DNS lookups with configurable timeout and upstream server.
type Resolver struct {
	Upstream string
	Timeout  time.Duration
}

// NewResolver creates a new Resolver with the given upstream DNS server and timeout.
func NewResolver(upstream string, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		Upstream: upstream,
		Timeout:  timeout,
	}
}

// Resolve performs a DNS lookup for the given hostname using the configured upstream.
func (r *Resolver) Resolve(hostname string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.Timeout}
			return d.DialContext(ctx, "udp", r.Upstream)
		},
	}

	// Use the custom resolver so lookups actually go through r.Upstream
	addrs, err := resolver.LookupHost(context.Background(), hostname)
	if err != nil {
		return nil, fmt.Errorf("dns resolve %q via %s: %w", hostname, r.Upstream, err)
	}

	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// ResolveFirst returns the first IP address resolved for hostname, or an error.
func (r *Resolver) ResolveFirst(hostname string) (net.IP, error) {
	ips, err := r.Resolve(hostname)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns resolve %q: no results", hostname)
	}
	return ips[0], nil
}
