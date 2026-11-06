// Package server accepts WideConnect TCP connections and dispatches frames.
package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/TCOxAV/WideConnect/protocol"
)

// Server listens for WideConnect peers.
type Server struct {
	addr string
	wg   sync.WaitGroup
}

// New returns a Server that will listen on addr (e.g. ":7777").
func New(addr string) *Server {
	return &Server{addr: addr}
}

// ListenAndServe blocks until ctx is cancelled, then closes the listener
// and all connections and waits for handlers to finish.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", ln.Addr())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			log.Printf("accept: %v", err)
			time.Sleep(50 * time.Millisecond) // avoid a hot loop on persistent errors
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	log.Printf("[%s] connected", remote)
	defer log.Printf("[%s] disconnected", remote)

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) // Go's default, but explicit: latency is the whole point
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Closing the conn is how we unblock a pending read on shutdown.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	r := bufio.NewReader(conn)
	for {
		f, err := protocol.ReadFrame(r)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				log.Printf("[%s] read: %v", remote, err)
			}
			return
		}

		switch f.Type {
		case protocol.TypePing:
			pong := protocol.Frame{Type: protocol.TypePong, Payload: f.Payload}
			if err := protocol.WriteFrame(conn, pong); err != nil {
				log.Printf("[%s] write: %v", remote, err)
				return
			}
		default:
			log.Printf("[%s] unhandled frame type %#x", remote, f.Type)
		}
	}
}
