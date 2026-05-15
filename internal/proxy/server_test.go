package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNew_InvalidConfig(t *testing.T) {
	cfg := Config{} // missing ListenAddr
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestNew_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Error("expected non-nil server")
	}
}

func TestServer_ListenAndServe_Cancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe(ctx)
	}()

	// Give the server a moment to start.
	// Increased from 50ms to 100ms to reduce flakiness on slow CI machines.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != ErrProxyClosed {
			t.Errorf("expected ErrProxyClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("server did not shut down in time")
	}
}

func TestServer_Close_Idempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	s, _ := New(cfg)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	s.listener = ln

	if err := s.Close(); err != nil {
		t.Fatalf("first Close error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
}

func TestServer_Addr_BeforeListen(t *testing.T) {
	cfg := DefaultConfig()
	s, _ := New(cfg)
	if addr := s.Addr(); addr != "" {
		t.Errorf("expected empty addr before listen, got %q", addr)
	}
}
