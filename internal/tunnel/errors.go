package tunnel

import "errors"

// Sentinel errors for tunnel configuration and operation.
var (
	ErrMissingLocalAddr    = errors.New("tunnel: local address is required")
	ErrMissingRemoteAddr   = errors.New("tunnel: remote address is required")
	ErrUnsupportedProtocol = errors.New("tunnel: unsupported protocol, must be tcp or udp")
	ErrInvalidBufferSize   = errors.New("tunnel: buffer size must be greater than zero")
	ErrTunnelClosed        = errors.New("tunnel: tunnel is already closed")
)
