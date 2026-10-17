//go:build darwin

package transparent

import "syscall"

// listenErr reports no error: an ordinary listener does, as pf rdr rules
// redirect traffic to it and OriginalDestination looks up the original
// target with DIOCNATLOOK.
func listenErr() error { return nil }

//goland:noinspection GoUnusedParameter
func control(string, string, syscall.RawConn) error {
	return nil
}

//goland:noinspection GoUnusedParameter
func controlPacket(string, string, syscall.RawConn) error {
	return ErrListenUnsupported
}
