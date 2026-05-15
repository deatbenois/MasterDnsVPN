package tunnel

import "time"

// Protocol represents the tunnel protocol type.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Config holds configuration for a tunnel connection.
type Config struct {
	// LocalAddr is the local address to listen on (e.g. "0.0.0.0:8080").
	LocalAddr string
	// RemoteAddr is the remote address to forward traffic to.
	RemoteAddr string
	// Protocol is the network protocol to use (tcp or udp).
	Protocol Protocol
	// DialTimeout is the timeout for establishing a connection to the remote.
	DialTimeout time.Duration
	// BufferSize is the size in bytes of the copy buffer.
	BufferSize int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Protocol:    ProtocolTCP,
		DialTimeout: 10 * time.Second,
		BufferSize:  32 * 1024,
	}
}

// Validate checks that the Config fields are valid.
func (c Config) Validate() error {
	if c.LocalAddr == "" {
		return ErrMissingLocalAddr
	}
	if c.RemoteAddr == "" {
		return ErrMissingRemoteAddr
	}
	if c.Protocol != ProtocolTCP && c.Protocol != ProtocolUDP {
		return ErrUnsupportedProtocol
	}
	if c.BufferSize <= 0 {
		return ErrInvalidBufferSize
	}
	return nil
}
