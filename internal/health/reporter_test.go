package health

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewReport_AllAlive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewChecker(3 * time.Second)
	report := NewReport(c, nil, []string{ts.URL})

	if len(report.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Results))
	}
	if !report.AllAlive() {
		t.Error("expected AllAlive=true")
	}
}

func TestNewReport_NotAllAlive(t *testing.T) {
	c := NewChecker(1 * time.Second)
	report := NewReport(c, []string{"127.0.0.1:1"}, nil)

	if report.AllAlive() {
		t.Error("expected AllAlive=false for unreachable endpoint")
	}
}

func TestReport_Print(t *testing.T) {
	report := &Report{
		Timestamp: time.Now(),
		Results: []Status{
			{Endpoint: "example.com:80", Alive: true, Latency: 10 * time.Millisecond},
			{Endpoint: "bad.host:1", Alive: false, Latency: 1 * time.Second, Error: "connection refused"},
		},
	}

	var buf bytes.Buffer
	report.Print(&buf)
	out := buf.String()

	if !strings.Contains(out, "Health Report") {
		t.Error("expected 'Health Report' header in output")
	}
	if !strings.Contains(out, "[OK]") {
		t.Error("expected '[OK]' in output")
	}
	if !strings.Contains(out, "[FAIL]") {
		t.Error("expected '[FAIL]' in output")
	}
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error message in output")
	}
}

func TestReport_Print_NilWriter(t *testing.T) {
	report := &Report{
		Timestamp: time.Now(),
		Results:   []Status{{Endpoint: "localhost", Alive: true}},
	}
	// Should not panic when writer is nil (falls back to os.Stdout)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Print panicked with nil writer: %v", r)
		}
	}()
	report.Print(nil)
}
