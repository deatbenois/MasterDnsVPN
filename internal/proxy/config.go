package proxy

import (
	"errors"
	"time"
)

// Protocol represents the proxy protocol type.
type Protocol string

const (
	ProtocolSOCKS5 Protocol = "socks5"
	ProtocolHTTP   Protocol = "http"

	DefaultDialTimeout  = 10 * time.Second
	DefaultReadTimeout  = 30 * time.Second
	DefaultWriteTimeout = 30 * time.Second
)

// Config holds the configuration for a proxy server.
type Config struct {
	ListenAddr   string
	Protocol     Protocol
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Username     string
	Password     string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:   "127.0.0.1:1080",
		Protocol:     ProtocolSOCKS5,
		DialTimeout:  DefaultDialTimeout,
		ReadTimeout:  DefaultReadTimeout,
		WriteTimeout: DefaultWriteTimeout,
	}
}

// Validate checks that the Config is valid.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("proxy: listen address is required")
	}
	if c.Protocol != ProtocolSOCKS5 && c.Protocol != ProtocolHTTP {
		return errors.New("proxy: unsupported protocol, must be socks5 or http")
	}
	if c.DialTimeout <= 0 {
		return errors.New("proxy: dial timeout must be positive")
	}
	return nil
}
