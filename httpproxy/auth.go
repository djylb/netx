package httpproxy

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/internal/creds"
)

// Authenticator authenticates the proxy requests of clients with one
// scheme, from their Proxy-Authorization field (RFC 9110, section 11.7.2).
type Authenticator interface {
	// Scheme returns the authentication scheme, such as "Basic", which is
	// matched case-insensitively, or "" for an authenticator of requests
	// without credentials, as NoAuth is.
	Scheme() string
	// Authenticate checks the credentials of req, the Proxy-Authorization
	// value after the scheme, empty for the "" scheme, and returns the
	// client's identity. Its decision holds for the later requests of the
	// connection with the same Proxy-Authorization value, which are not
	// passed to it again, so decide on the client, not on the destination,
	// which is Allow's. ErrAuthRequired and ErrAuthFailed are answered
	// with 407 and the challenges of the server's authenticators; other
	// errors with their StatusFor code, 503 Service Unavailable when that
	// is 502, as for an unreachable account backend.
	Authenticate(ctx context.Context, req *Request, credentials string) (user string, err error)
	// Challenge returns the Proxy-Authenticate value that asks for the
	// scheme, such as `Basic realm="proxy"`; it is not used for the ""
	// scheme.
	Challenge() string
}

// NoAuth accepts requests without authentication.
type NoAuth struct{}

// Scheme returns "".
func (NoAuth) Scheme() string { return "" }

// Authenticate accepts the request.
func (NoAuth) Authenticate(context.Context, *Request, string) (string, error) { return "", nil }

// Challenge returns "".
func (NoAuth) Challenge() string { return "" }

// BasicAuth checks Basic credentials (RFC 7617).
type BasicAuth struct {
	// Realm is the realm of the challenge; "proxy" if empty.
	Realm string
	// Check reports whether the credentials that the client sent on c, the
	// connection being served, are valid, as socks5.UserPassAuth.Check
	// does, so that one function can check the clients of both servers; ctx
	// is bounded by the handshake.
	// An error, such as an unreachable account backend, rejects the client
	// too and is returned by Authenticate instead of ErrAuthFailed. Nil
	// rejects all credentials. See Credentials for a fixed account list.
	Check func(ctx context.Context, c net.Conn, user, password string) (bool, error)
}

// Scheme returns "Basic".
func (BasicAuth) Scheme() string { return "Basic" }

// Challenge returns the Basic challenge for the realm.
func (a BasicAuth) Challenge() string {
	realm := a.Realm
	if realm == "" {
		realm = "proxy"
	}
	return "Basic realm=" + strconv.Quote(realm) + `, charset="UTF-8"`
}

// Authenticate decodes the credentials, checks them and returns the user
// name, or ErrAuthFailed, or the error of Check. Base64 with or without
// padding is accepted.
func (a BasicAuth) Authenticate(ctx context.Context, req *Request, credentials string) (string, error) {
	credentials = httphead.TrimOWS(credentials)
	decoded, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(credentials)
	}
	if err != nil {
		return "", ErrAuthFailed
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	if !ok || a.Check == nil {
		return "", ErrAuthFailed
	}
	c := req.conn.Conn
	if c == nil {
		c = req.Conn // a Request made by the caller
	}
	valid, err := a.Check(ctx, c, user, password)
	switch {
	case err != nil:
		return "", err
	case !valid:
		return "", ErrAuthFailed
	}
	return user, nil
}

// Credentials returns a BasicAuth that accepts the given user names and
// passwords, for a server with a fixed account list:
//
//	s := &httpproxy.Server{Auth: []httpproxy.Authenticator{httpproxy.Credentials(accounts)}}
//
// It compares SHA-256 digests in constant time, and for unknown users
// compares against a digest of no account, so that the time taken tells
// neither the length of a password nor whether a user exists, as
// socks5.Credentials does. accounts is read once.
func Credentials(accounts map[string]string) BasicAuth {
	a := creds.New(accounts)
	return BasicAuth{Check: func(_ context.Context, _ net.Conn, user, password string) (bool, error) {
		return a.Check(user, password), nil
	}}
}
