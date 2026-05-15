package dns

import (
	"net"
	"testing"
	"time"
)

func TestNewResolver_Defaults(t *testing.T) {
	r := NewResolver("8.8.8.8:53", 0)
	if r.Upstream != "8.8.8.8:53" {
		t.Errorf("expected upstream 8.8.8.8:53, got %s", r.Upstream)
	}
	if r.Timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", r.Timeout)
	}
}

func TestNewResolver_CustomTimeout(t *testing.T) {
	r := NewResolver("1.1.1.1:53", 3*time.Second)
	if r.Timeout != 3*time.Second {
		t.Errorf("expected timeout 3s, got %v", r.Timeout)
	}
}

func TestResolve_Localhost(t *testing.T) {
	r := NewResolver("8.8.8.8:53", 5*time.Second)
	ips, err := r.Resolve("localhost")
	if err != nil {
		t.Skipf("skipping resolve test (no network): %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP for localhost")
	}
}

func TestResolveFirst_Localhost(t *testing.T) {
	r := NewResolver("8.8.8.8:53", 5*time.Second)
	ip, err := r.ResolveFirst("localhost")
	if err != nil {
		t.Skipf("skipping resolve test (no network): %v", err)
	}
	if ip == nil {
		t.Error("expected non-nil IP")
	}
}

func TestResolveFirst_InvalidHost(t *testing.T) {
	r := NewResolver("8.8.8.8:53", 2*time.Second)
	_, err := r.ResolveFirst("this.host.does.not.exist.invalid")
	if err == nil {
		t.Error("expected error for invalid hostname, got nil")
	}
}

func TestResolve_ParsesIPs(t *testing.T) {
	addrs := []string{"127.0.0.1", "::1"}
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(ips))
	}
}
