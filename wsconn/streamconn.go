package wsconn

import (
	"errors"
	"io"
	"net"
	"time"
)

// StreamConn is a net.Conn that carries a byte stream over the binary
// messages of a Conn, for tunnels: each Write sends one message, of one
// frame, and Read reads the messages one after the other, across their
// bounds, and also accepts text messages. A close frame with status 1000,
// 1001 or none, and the end of the connection beneath between frames, end
// the stream with io.EOF; other close frames are read as a *CloseError.
//
// Read follows the one-reader rule of Conn: while a StreamConn reads, the
// Conn's own read methods must not be used.
type StreamConn struct {
	c *Conn
}

// NewStreamConn returns the stream over c's messages.
func NewStreamConn(c *Conn) *StreamConn { return &StreamConn{c: c} }

// Conn returns the WebSocket connection, for its message API, pings and
// close codes.
func (s *StreamConn) Conn() *Conn { return s.c }

// NetConn returns the connection beneath the WebSocket connection, as
// Conn.NetConn does.
func (s *StreamConn) NetConn() net.Conn { return s.c.conn }

// Read reads the payload of the stream's messages.
func (s *StreamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c := s.c
	c.rsem <- struct{}{}
	defer func() { <-c.rsem }()
	for {
		if c.rmsg == 0 {
			if _, err := c.beginMessage(-1); err != nil {
				return 0, streamErr(err)
			}
		}
		n, err := c.readMessage(p)
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, streamErr(err)
		}
	}
}

// streamErr returns the error that a StreamConn's Read returns for err.
func streamErr(err error) error {
	var ce *CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case StatusNormalClosure, StatusGoingAway, StatusNoStatusReceived:
			return io.EOF
		}
	}
	return err
}

// Write sends p as one binary message.
func (s *StreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := s.c.WriteMessage(Binary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the WebSocket connection as Conn.Close does.
func (s *StreamConn) Close() error { return s.c.Close() }

// LocalAddr returns the local address of the connection beneath.
func (s *StreamConn) LocalAddr() net.Addr { return s.c.conn.LocalAddr() }

// RemoteAddr returns the remote address of the connection beneath, with
// its port.
func (s *StreamConn) RemoteAddr() net.Addr { return s.c.conn.RemoteAddr() }

// SetDeadline sets the deadlines of the connection beneath.
func (s *StreamConn) SetDeadline(t time.Time) error { return s.c.SetDeadline(t) }

// SetReadDeadline sets the read deadline of the connection beneath.
func (s *StreamConn) SetReadDeadline(t time.Time) error { return s.c.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline of the connection beneath.
func (s *StreamConn) SetWriteDeadline(t time.Time) error { return s.c.SetWriteDeadline(t) }
