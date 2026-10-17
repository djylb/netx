package netx

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// ErrGroupClosed is returned by ConnGroup.Add on a group that Close closed.
var ErrGroupClosed = errors.New("netx: connection group closed")

// ConnGroup tracks connections, or anything else that closes, so that they
// can be closed together, such as every connection of one user when its
// allowance runs out or the service is disabled. A connection may be in
// several groups, such as those of its user, client and service, and a group
// may be in another: closing the members of the outer group closes those of
// the inner one, and closing the outer group closes the inner one. A Relay
// joins with WithRelayGroup, which also ends a RelayFlow.Wait that blocks.
// Its methods are safe for concurrent use. The zero value is an empty, open
// group.
type ConnGroup struct {
	mu     sync.Mutex
	conns  map[*groupMember]struct{}
	closed bool
}

type groupMember struct {
	c io.Closer
}

// memberCloser is a member that closes with a cause: a relay, which returns
// it, or a group, which passes it on.
type memberCloser interface {
	closeMember(cause error, final bool) error
}

// Add adds c and returns a function that removes it again, which the owner
// of c calls once it is done with c, closed or not; calling it more than once
// is harmless. On a group that Close closed, Add returns ErrGroupClosed and
// leaves c to its owner.
func (g *ConnGroup) Add(c io.Closer) (remove func(), err error) {
	m := &groupMember{c: c}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return func() {}, ErrGroupClosed
	}
	if g.conns == nil {
		g.conns = make(map[*groupMember]struct{})
	}
	g.conns[m] = struct{}{}
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		delete(g.conns, m)
		g.mu.Unlock()
	}, nil
}

// Track adds c, as Add does, and returns c wrapped so that closing it also
// removes it from the group, which then needs no remove call. Relay looks
// through the wrapper as through c. On a group that Close closed, Track
// returns ErrGroupClosed and leaves c to its owner.
func (g *ConnGroup) Track(c net.Conn) (net.Conn, error) {
	remove, err := g.Add(c)
	if err != nil {
		return nil, err
	}
	return &trackedConn{conn: c, remove: remove}, nil
}

// trackedConn is a connection of a ConnGroup that leaves it on Close.
type trackedConn struct {
	conn   net.Conn
	remove func()
}

func (c *trackedConn) Read(b []byte) (int, error)  { return c.conn.Read(b) }
func (c *trackedConn) Write(b []byte) (int, error) { return c.conn.Write(b) }

// Close closes the connection and removes it from its group.
func (c *trackedConn) Close() error {
	err := c.conn.Close()
	c.remove()
	return err
}

func (c *trackedConn) CloseWrite() error                  { return closeWrite(c.conn) }
func (c *trackedConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *trackedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *trackedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *trackedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *trackedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *trackedConn) innerReader() io.Reader             { return c.conn }

// NetConn returns the connection that c wraps; see InnermostConn.
func (c *trackedConn) NetConn() net.Conn { return c.conn }

// Len returns the number of members in the group: connections, groups, and
// relays that joined with WithRelayGroup.
func (g *ConnGroup) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.conns)
}

// CloseMembers closes the members of the group and removes them; the group
// takes new ones afterwards. Relays among them return cause too, if it is
// not nil, and groups among them close their own members the same way and
// stay open. It returns the errors of the members' Close methods, joined.
// The members are closed without the group's lock, so a Close that blocks,
// as a TLS connection's may, holds up neither Add nor removes.
func (g *ConnGroup) CloseMembers(cause error) error {
	return g.closeAll(cause, false)
}

// Close closes the members of the group, as CloseMembers does but closing
// groups among them for good too, and makes Add refuse new members.
func (g *ConnGroup) Close() error {
	return g.closeAll(nil, true)
}

func (g *ConnGroup) closeMember(cause error, final bool) error {
	return g.closeAll(cause, final)
}

func (g *ConnGroup) closeAll(cause error, final bool) error {
	g.mu.Lock()
	if final {
		g.closed = true
	}
	members := g.conns
	g.conns = nil
	g.mu.Unlock()
	var errs []error
	for m := range members {
		var err error
		if mc, ok := m.c.(memberCloser); ok {
			err = mc.closeMember(cause, final)
		} else {
			err = m.c.Close()
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
