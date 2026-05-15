package dns

import (
	"net"
	"sync"
	"time"
)

// cacheEntry holds resolved IPs and an expiry timestamp.
type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

// Cache is a simple TTL-based in-memory DNS cache.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	TTL     time.Duration
}

// NewCache creates a Cache with the given TTL for entries.
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Cache{
		entries: make(map[string]cacheEntry),
		TTL:     ttl,
	}
}

// Get retrieves cached IPs for hostname. Returns nil, false if missing or expired.
func (c *Cache) Get(hostname string) ([]net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[hostname]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.ips, true
}

// Set stores IPs for hostname with the configured TTL.
func (c *Cache) Set(hostname string, ips []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[hostname] = cacheEntry{
		ips:     ips,
		expires: time.Now().Add(c.TTL),
	}
}

// Invalidate removes the cache entry for hostname.
func (c *Cache) Invalidate(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, hostname)
}

// Flush clears all cache entries.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}
