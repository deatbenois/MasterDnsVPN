package proxy

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ListenAddr == "" {
		t.Error("expected non-empty ListenAddr")
	}
	if cfg.Protocol != ProtocolSOCKS5 {
		t.Errorf("expected socks5, got %s", cfg.Protocol)
	}
	if cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("expected %v, got %v", DefaultDialTimeout, cfg.DialTimeout)
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_MissingListenAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing ListenAddr")
	}
}

func TestConfig_Validate_BadProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = "ftp"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestConfig_Validate_ZeroDialTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DialTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero DialTimeout")
	}
}

func TestConfig_Validate_HTTPProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = ProtocolHTTP
	cfg.DialTimeout = 5 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
