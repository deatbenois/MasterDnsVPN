package proxy

import (
	"context"
	"net"
	"sync"
)

// Server is a proxy server that accepts and forwards connections.
type Server struct {
	cfg      Config
	listener net.Listener
	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup
}

// New creates a new proxy Server with the given Config.
func New(cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg}, nil
}

// ListenAndServe starts listening and serves incoming connections until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrProxyClosed
			}
			return err
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handle(c)
		}(conn)
	}
}

// Close shuts down the server gracefully.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the server's listening address, or empty string if not listening.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// handle dispatches the connection to the appropriate protocol handler.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	conn.(*net.TCPConn).SetKeepAlive(true) //nolint:errcheck
	// Protocol-specific handling would be dispatched here.
	// For now, connections are accepted and cleanly closed.
}
