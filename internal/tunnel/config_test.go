package tunnel

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Protocol != ProtocolTCP {
		t.Errorf("expected protocol %q, got %q", ProtocolTCP, cfg.Protocol)
	}
	if cfg.DialTimeout != 10*time.Second {
		t.Errorf("expected dial timeout 10s, got %v", cfg.DialTimeout)
	}
	if cfg.BufferSize != 32*1024 {
		t.Errorf("expected buffer size 32768, got %d", cfg.BufferSize)
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:9000"
	cfg.RemoteAddr = "127.0.0.1:9001"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestConfig_Validate_MissingLocal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RemoteAddr = "127.0.0.1:9001"
	if err := cfg.Validate(); err != ErrMissingLocalAddr {
		t.Errorf("expected ErrMissingLocalAddr, got %v", err)
	}
}

func TestConfig_Validate_MissingRemote(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:9000"
	if err := cfg.Validate(); err != ErrMissingRemoteAddr {
		t.Errorf("expected ErrMissingRemoteAddr, got %v", err)
	}
}

func TestConfig_Validate_BadProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:9000"
	cfg.RemoteAddr = "127.0.0.1:9001"
	cfg.Protocol = "sctp"
	if err := cfg.Validate(); err != ErrUnsupportedProtocol {
		t.Errorf("expected ErrUnsupportedProtocol, got %v", err)
	}
}

func TestConfig_Validate_BadBufferSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:9000"
	cfg.RemoteAddr = "127.0.0.1:9001"
	cfg.BufferSize = 0
	if err := cfg.Validate(); err != ErrInvalidBufferSize {
		t.Errorf("expected ErrInvalidBufferSize, got %v", err)
	}
}

// TestConfig_Validate_NegativeBufferSize checks that a negative buffer size
// is also treated as invalid, not just zero.
func TestConfig_Validate_NegativeBufferSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:9000"
	cfg.RemoteAddr = "127.0.0.1:9001"
	cfg.BufferSize = -1
	if err := cfg.Validate(); err != ErrInvalidBufferSize {
		t.Errorf("expected ErrInvalidBufferSize for negative size, got %v", err)
	}
}
