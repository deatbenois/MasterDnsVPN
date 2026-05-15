package health

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewChecker(t *testing.T) {
	c := NewChecker(5 * time.Second)
	if c == nil {
		t.Fatal("expected non-nil Checker")
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", c.Timeout)
	}
}

func TestCheckTCP_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	c := NewChecker(3 * time.Second)
	status := c.CheckTCP(ln.Addr().String())
	if !status.Alive {
		t.Errorf("expected alive=true, got error: %s", status.Error)
	}
}

func TestCheckTCP_Failure(t *testing.T) {
	c := NewChecker(1 * time.Second)
	status := c.CheckTCP("127.0.0.1:1")
	if status.Alive {
		t.Error("expected alive=false for unreachable port")
	}
	if status.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestCheckHTTP_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewChecker(3 * time.Second)
	status := c.CheckHTTP(ts.URL)
	if !status.Alive {
		t.Errorf("expected alive=true, got error: %s", status.Error)
	}
}

func TestCheckHTTP_Failure(t *testing.T) {
	c := NewChecker(1 * time.Second)
	status := c.CheckHTTP("http://127.0.0.1:1/test")
	if status.Alive {
		t.Error("expected alive=false for unreachable server")
	}
}

func TestCheckDNS_Success(t *testing.T) {
	c := NewChecker(3 * time.Second)
	status := c.CheckDNS("localhost")
	if !status.Alive {
		t.Errorf("expected alive=true for localhost, got: %s", status.Error)
	}
}

func TestCheckDNS_Failure(t *testing.T) {
	c := NewChecker(3 * time.Second)
	status := c.CheckDNS("this.domain.does.not.exist.invalid")
	if status.Alive {
		t.Error("expected alive=false for invalid domain")
	}
}
