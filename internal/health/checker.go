package health

import (
	"net"
	"net/http"
	"time"
)

// Status represents the health status of a service endpoint.
type Status struct {
	Endpoint string
	Alive    bool
	Latency  time.Duration
	Error    string
}

// Checker performs health checks on DNS and VPN endpoints.
type Checker struct {
	Timeout time.Duration
	Client  *http.Client
}

// NewChecker creates a new Checker with the given timeout.
func NewChecker(timeout time.Duration) *Checker {
	return &Checker{
		Timeout: timeout,
		Client: &http.Client{
			Timeout: timeout,
		},
	}
}

// CheckTCP tests a TCP endpoint and returns its Status.
func (c *Checker) CheckTCP(address string) Status {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, c.Timeout)
	latency := time.Since(start)
	if err != nil {
		return Status{Endpoint: address, Alive: false, Latency: latency, Error: err.Error()}
	}
	conn.Close()
	return Status{Endpoint: address, Alive: true, Latency: latency}
}

// CheckHTTP tests an HTTP endpoint and returns its Status.
func (c *Checker) CheckHTTP(url string) Status {
	start := time.Now()
	resp, err := c.Client.Get(url)
	latency := time.Since(start)
	if err != nil {
		return Status{Endpoint: url, Alive: false, Latency: latency, Error: err.Error()}
	}
	resp.Body.Close()
	alive := resp.StatusCode >= 200 && resp.StatusCode < 400
	return Status{Endpoint: url, Alive: alive, Latency: latency}
}

// CheckDNS tests DNS resolution for the given host.
func (c *Checker) CheckDNS(host string) Status {
	start := time.Now()
	_, err := net.LookupHost(host)
	latency := time.Since(start)
	if err != nil {
		return Status{Endpoint: host, Alive: false, Latency: latency, Error: err.Error()}
	}
	return Status{Endpoint: host, Alive: true, Latency: latency}
}
