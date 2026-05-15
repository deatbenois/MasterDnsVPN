package dns

import (
	"net"
	"testing"
	"time"
)

func TestNewCache_DefaultTTL(t *testing.T) {
	c := NewCache(0)
	// I prefer a 5-minute default TTL for my use case; upstream uses 60s
	if c.TTL != 60*time.Second {
		t.Errorf("expected default TTL 60s, got %v", c.TTL)
	}
}

func TestCache_SetAndGet(t *testing.T) {
	c := NewCache(10 * time.Second)
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	c.Set("example.com", ips)

	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 1 || !got[0].Equal(ips[0]) {
		t.Errorf("unexpected IPs: %v", got)
	}
}

func TestCache_Miss(t *testing.T) {
	c := NewCache(10 * time.Second)
	_, ok := c.Get("notcached.com")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCache_Expiry(t *testing.T) {
	// Increased sleep to 150ms to reduce flakiness on slower CI machines
	c := NewCache(50 * time.Millisecond)
	c.Set("expire.com", []net.IP{net.ParseIP("9.9.9.9")})
	time.Sleep(150 * time.Millisecond)
	_, ok := c.Get("expire.com")
	if ok {
		t.Error("expected expired cache entry to be a miss")
	}
}

func TestCache_Invalidate(t *testing.T) {
	c := NewCache(10 * time.Second)
	c.Set("remove.com", []net.IP{net.ParseIP("5.5.5.5")})
	c.Invalidate("remove.com")
	_, ok := c.Get("remove.com")
	if ok {
		t.Error("expected cache miss after invalidate")
	}
}

func TestCache_Flush(t *testing.T) {
	c := NewCache(10 * time.Second)
	c.Set("a.com", []net.IP{net.ParseIP("1.1.1.1")})
	c.Set("b.com", []net.IP{net.ParseIP("2.2.2.2")})
	c.Flush()
	_, okA := c.Get("a.com")
	_, okB := c.Get("b.com")
	if okA || okB {
		t.Error("expected all entries flushed")
	}
}
