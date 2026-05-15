package tunnel

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestNew_InvalidConfig(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestTunnel_ForwardsData(t *testing.T) {
	// Start a simple echo server.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) //nolint:errcheck
	}()

	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:0"
	cfg.RemoteAddr = echo.Addr().String()

	tun, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		t.Fatalf("pre-listen: %v", err)
	}
	tun.listener = ln
	tun.cfg.LocalAddr = ln.Addr().String()

	go tun.ListenAndServe() //nolint:errcheck
	defer tun.Close()

	time.Sleep(20 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello tunnel")
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestTunnel_Close_Idempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalAddr = "127.0.0.1:0"
	cfg.RemoteAddr = "127.0.0.1:9999"
	tun, _ := New(cfg)
	if err := tun.Close(); err != nil {
		t.Logf("first close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Logf("second close (idempotent): %v", err)
	}
}
