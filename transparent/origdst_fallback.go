//go:build linux || freebsd

package transparent

import "errors"

// errNotRedirected marks a lookup that found no redirect for a connection,
// which OriginalDestination answers with the connection's local address.
var errNotRedirected = errors.New("not a redirected connection")
