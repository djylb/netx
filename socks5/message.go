package socks5

import "io"

// ReadMethods reads a client's version identifier/method selection message
// and returns the offered methods.
func ReadMethods(r io.Reader) ([]Method, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version {
		return nil, ErrVersion
	}
	var buf [255]byte
	if _, err := io.ReadFull(r, buf[:hdr[1]]); err != nil {
		return nil, unexpectedEOF(err)
	}
	methods := make([]Method, hdr[1])
	for i, m := range buf[:hdr[1]] {
		methods[i] = Method(m)
	}
	return methods, nil
}

// WriteMethods writes a client's method selection message offering methods.
// It returns ErrMalformed if methods is empty or longer than 255.
func WriteMethods(w io.Writer, methods ...Method) error {
	if len(methods) == 0 || len(methods) > 255 {
		return ErrMalformed
	}
	msg := make([]byte, 0, 2+len(methods))
	msg = append(msg, Version, byte(len(methods)))
	for _, m := range methods {
		msg = append(msg, byte(m))
	}
	return write(w, msg)
}

// WriteMethod writes the server's method selection. MethodNoAcceptable tells
// the client that none of its methods were accepted; the server then closes
// the connection.
func WriteMethod(w io.Writer, m Method) error {
	return write(w, []byte{Version, byte(m)})
}

// ReadMethod reads the server's method selection. It returns
// ErrNoAcceptableMethod when the server selects MethodNoAcceptable. The
// caller should check that the method is one it offered.
func ReadMethod(r io.Reader) (Method, error) {
	var msg [2]byte
	if _, err := io.ReadFull(r, msg[:]); err != nil {
		return 0, err
	}
	if msg[0] != Version {
		return 0, ErrVersion
	}
	if Method(msg[1]) == MethodNoAcceptable {
		return MethodNoAcceptable, ErrNoAcceptableMethod
	}
	return Method(msg[1]), nil
}

// ReadUserPass reads a username/password request.
func ReadUserPass(r io.Reader) (user, password string, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", "", err
	}
	if hdr[0] != userPassVersion {
		return "", "", ErrVersion
	}
	// The username is followed by the password length.
	var buf [256]byte
	ulen := int(hdr[1])
	if _, err := io.ReadFull(r, buf[:ulen+1]); err != nil {
		return "", "", unexpectedEOF(err)
	}
	user = string(buf[:ulen])
	plen := int(buf[ulen])
	if _, err := io.ReadFull(r, buf[:plen]); err != nil {
		return "", "", unexpectedEOF(err)
	}
	return user, string(buf[:plen]), nil
}

// WriteUserPass writes a username/password request. It returns ErrMalformed
// if user or password is longer than 255 bytes.
func WriteUserPass(w io.Writer, user, password string) error {
	if len(user) > 255 || len(password) > 255 {
		return ErrMalformed
	}
	msg := make([]byte, 0, 3+len(user)+len(password))
	msg = append(msg, userPassVersion, byte(len(user)))
	msg = append(msg, user...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, password...)
	return write(w, msg)
}

// WriteUserPassStatus writes the server's answer to a username/password
// request. After a failure the server closes the connection.
func WriteUserPassStatus(w io.Writer, ok bool) error {
	status := byte(1)
	if ok {
		status = 0
	}
	return write(w, []byte{userPassVersion, status})
}

// ReadUserPassStatus reads the server's answer to a username/password
// request and returns ErrAuthFailed if it is a failure.
func ReadUserPassStatus(r io.Reader) error {
	var msg [2]byte
	if _, err := io.ReadFull(r, msg[:]); err != nil {
		return err
	}
	if msg[0] != userPassVersion {
		return ErrVersion
	}
	if msg[1] != 0 {
		return ErrAuthFailed
	}
	return nil
}

// ReadRequest reads a client request. The command is returned as sent;
// answer commands the server does not implement with
// ReplyCommandNotSupported. ErrAddrType is answered with
// ReplyAddrTypeNotSupported.
func ReadRequest(r io.Reader) (Command, Addr, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, Addr{}, err
	}
	if hdr[0] != Version {
		return 0, Addr{}, ErrVersion
	}
	if hdr[2] != 0 {
		return 0, Addr{}, ErrMalformed
	}
	addr, err := ReadAddr(r)
	if err != nil {
		return 0, Addr{}, err
	}
	return Command(hdr[1]), addr, nil
}

// WriteRequest writes a client request for cmd to dst.
func WriteRequest(w io.Writer, cmd Command, dst Addr) error {
	return writeMessage(w, byte(cmd), dst)
}

// WriteReply writes a server reply carrying the bound address. Failure
// replies usually carry the zero Addr.
func WriteReply(w io.Writer, rep Reply, bound Addr) error {
	return writeMessage(w, byte(rep), bound)
}

// ReadReply reads a server reply and returns the bound address. A reply other
// than ReplySucceeded is returned as a *ReplyError.
func ReadReply(r io.Reader) (Addr, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Addr{}, err
	}
	if hdr[0] != Version {
		return Addr{}, ErrVersion
	}
	addr, err := ReadAddr(r)
	if err != nil {
		return Addr{}, err
	}
	if rep := Reply(hdr[1]); rep != ReplySucceeded {
		return addr, &ReplyError{Reply: rep}
	}
	return addr, nil
}

// writeMessage writes a request or reply: version, code, reserved byte and
// address.
func writeMessage(w io.Writer, code byte, addr Addr) error {
	var buf [3 + MaxAddrLen]byte
	msg, err := addr.AppendBinary(append(buf[:0], Version, code, 0))
	if err != nil {
		return err
	}
	return write(w, msg)
}

func write(w io.Writer, msg []byte) error {
	n, err := w.Write(msg)
	if err == nil && n < len(msg) {
		err = io.ErrShortWrite
	}
	return err
}
