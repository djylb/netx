package socks5

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"

	"github.com/djylb/netx"
)

var errSOCKS4Auth = errors.New("socks5: SOCKS4 request while authentication is required")

// handshake4 reads a SOCKS4 or SOCKS4a request whose version byte was read
// and runs the NoAuth authenticator, since SOCKS4 has no authentication.
// Every command is returned; ServeRequest refuses those it does not serve.
func (s *Server) handshake4(ctx context.Context, c net.Conn, first []byte) (*Request, error) {
	// Buffered, so that the user ID and name are not read one byte per
	// read of the connection. Bytes the client sent after the request are
	// replayed before the rest of the connection.
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(first), c), 512)
	cmd, dst, userID, err := ReadRequest4(br)
	var early []byte
	if n := br.Buffered(); n > 0 && err == nil {
		buffered, _ := br.Peek(n)
		early = bytes.Clone(buffered)
	}
	if err != nil {
		if errors.Is(err, ErrMalformed) {
			_ = WriteReply4(c, Reply4Rejected, netx.Addr{})
		}
		return nil, err
	}
	noAuth := s.noAuth()
	if noAuth == nil {
		_ = WriteReply4(c, Reply4Rejected, netx.Addr{})
		return nil, errSOCKS4Auth
	}
	user, err := noAuth.Authenticate(ctx, c)
	if err != nil {
		_ = WriteReply4(c, Reply4Rejected, netx.Addr{})
		return nil, err
	}
	req := &Request{Version: Version4, Command: cmd, Dst: dst, User: user, UserID4: userID, Conn: c}
	if len(early) > 0 {
		req.Conn = netx.NewPrefixConn(c, early)
	}
	return req, nil
}
