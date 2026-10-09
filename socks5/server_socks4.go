package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

var errSOCKS4Auth = errors.New("socks5: SOCKS4 request while authentication is required")

// handshake4 reads a SOCKS4 or SOCKS4a request whose version byte was read
// and runs the NoAuth authenticator, since SOCKS4 has no authentication.
func (s *Server) handshake4(ctx context.Context, c net.Conn, first []byte) (*Request, error) {
	cmd, dst, _, err := ReadRequest4(io.MultiReader(bytes.NewReader(first), c))
	if err != nil {
		if errors.Is(err, ErrMalformed) {
			_ = WriteReply4(c, Reply4Rejected, Addr{})
		}
		return nil, err
	}
	noAuth := s.noAuth()
	if noAuth == nil {
		_ = WriteReply4(c, Reply4Rejected, Addr{})
		return nil, errSOCKS4Auth
	}
	user, err := noAuth.Authenticate(ctx, c)
	if err != nil {
		_ = WriteReply4(c, Reply4Rejected, Addr{})
		return nil, err
	}
	if cmd != CmdConnect {
		_ = WriteReply4(c, Reply4Rejected, Addr{})
		return nil, fmt.Errorf("socks5: unsupported SOCKS4 %v", cmd)
	}
	return &Request{Version: 4, Command: CmdConnect, Dst: dst, User: user, Conn: c}, nil
}
