package proxy

import "errors"

// Sentinel errors for the proxy package.
var (
	ErrProxyClosed       = errors.New("proxy: server is closed")
	ErrAuthFailed        = errors.New("proxy: authentication failed")
	ErrUnsupportedMethod = errors.New("proxy: unsupported authentication method")
	ErrInvalidRequest    = errors.New("proxy: invalid request")
)
