package health

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Report holds the results of multiple health checks.
type Report struct {
	Timestamp time.Time
	Results   []Status
}

// NewReport runs health checks on the given TCP addresses and HTTP URLs.
func NewReport(checker *Checker, tcpAddrs []string, httpURLs []string) *Report {
	r := &Report{Timestamp: time.Now()}
	for _, addr := range tcpAddrs {
		r.Results = append(r.Results, checker.CheckTCP(addr))
	}
	for _, url := range httpURLs {
		r.Results = append(r.Results, checker.CheckHTTP(url))
	}
	return r
}

// AllAlive returns true if every check in the report passed.
func (r *Report) AllAlive() bool {
	for _, s := range r.Results {
		if !s.Alive {
			return false
		}
	}
	return true
}

// Print writes a human-readable summary of the report to the given writer.
func (r *Report) Print(w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, "Health Report — %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Fprintln(w, "-------------------------------")
	for _, s := range r.Results {
		stateStr := "OK"
		if !s.Alive {
			stateStr = "FAIL"
		}
		if s.Error != "" {
			fmt.Fprintf(w, "[%s] %s  latency=%v  err=%s\n", stateStr, s.Endpoint, s.Latency.Round(time.Millisecond), s.Error)
		} else {
			fmt.Fprintf(w, "[%s] %s  latency=%v\n", stateStr, s.Endpoint, s.Latency.Round(time.Millisecond))
		}
	}
	fmt.Fprintln(w, "-------------------------------")
}
