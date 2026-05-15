package tunnel

import (
	"io"
	"log"
	"net"
	"sync"
)

// Tunnel listens on a local address and forwards connections to a remote address.
type Tunnel struct {
	cfg      Config
	listener net.Listener
	once     sync.Once
	done     chan struct{}
}

// New creates a new Tunnel with the given Config.
// Returns an error if the config is invalid.
func New(cfg Config) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Tunnel{
		cfg:  cfg,
		done: make(chan struct{}),
	}, nil
}

// ListenAndServe starts the tunnel, accepting and forwarding connections.
// It blocks until Close is called or a fatal error occurs.
func (t *Tunnel) ListenAndServe() error {
	ln, err := net.Listen(string(t.cfg.Protocol), t.cfg.LocalAddr)
	if err != nil {
		return err
	}
	t.listener = ln
	log.Printf("tunnel: listening on %s, forwarding to %s", t.cfg.LocalAddr, t.cfg.RemoteAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return nil
			default:
				return err
			}
		}
		go t.handle(conn)
	}
}

// handle forwards data between the local connection and the remote.
func (t *Tunnel) handle(local net.Conn) {
	defer local.Close()
	remote, err := net.DialTimeout(string(t.cfg.Protocol), t.cfg.RemoteAddr, t.cfg.DialTimeout)
	if err != nil {
		log.Printf("tunnel: dial remote %s: %v", t.cfg.RemoteAddr, err)
		return
	}
	defer remote.Close()

	// Log each successfully proxied connection for easier debugging.
	log.Printf("tunnel: proxying %s -> %s", local.RemoteAddr(), t.cfg.RemoteAddr)

	var wg sync.WaitGroup
	copy := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, t.cfg.BufferSize)
		io.CopyBuffer(dst, src, buf) //nolint:errcheck
	}
	wg.Add(2)
	go copy(remote, local)
	go copy(local, remote)
	wg.Wait()
}

// Close shuts down the tunnel listener.
func (t *Tunnel) Close() error {
	var err error
	t.once.Do(func() {
		close(t.done)
		if t.listener != nil {
			err = t.listener.Close()
		}
	})
	return err
}
