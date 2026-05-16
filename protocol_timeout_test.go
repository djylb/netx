package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type protocolDeadlineSpyConn struct {
	readBuf            *bytes.Reader
	writeBuf           bytes.Buffer
	firstReadDeadline  time.Time
	firstWriteDeadline time.Time
	readDeadlineErr    error
	writeDeadlineErr   error
}

type chunkedProtocolWriteConn struct {
	*protocolDeadlineSpyConn
	maxWrite int
}

func newProtocolDeadlineSpyConn(readPayload []byte) *protocolDeadlineSpyConn {
	return &protocolDeadlineSpyConn{readBuf: bytes.NewReader(readPayload)}
}

func (c *protocolDeadlineSpyConn) Read(p []byte) (int, error) {
	if c.readBuf == nil {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *protocolDeadlineSpyConn) Write(p []byte) (int, error) {
	return c.writeBuf.Write(p)
}

func (c *chunkedProtocolWriteConn) Write(p []byte) (int, error) {
	if c.maxWrite > 0 && len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.writeBuf.Write(p)
}

func (c *protocolDeadlineSpyConn) Close() error { return nil }

func (c *protocolDeadlineSpyConn) LocalAddr() net.Addr  { return dummyAddr("local") }
func (c *protocolDeadlineSpyConn) RemoteAddr() net.Addr { return dummyAddr("remote") }

func (c *protocolDeadlineSpyConn) SetDeadline(time.Time) error { return nil }

func (c *protocolDeadlineSpyConn) SetReadDeadline(t time.Time) error {
	if c.firstReadDeadline.IsZero() && !t.IsZero() {
		c.firstReadDeadline = t
	}
	if c.readDeadlineErr != nil {
		return c.readDeadlineErr
	}
	return nil
}

func (c *protocolDeadlineSpyConn) SetWriteDeadline(t time.Time) error {
	if c.firstWriteDeadline.IsZero() && !t.IsZero() {
		c.firstWriteDeadline = t
	}
	if c.writeDeadlineErr != nil {
		return c.writeDeadlineErr
	}
	return nil
}

func TestACKHelpersNormalizeNonPositiveTimeouts(t *testing.T) {
	writer := newProtocolDeadlineSpyConn(nil)
	startedWrite := time.Now()
	if err := WriteACK(writer, 0); err != nil {
		t.Fatalf("WriteACK() error = %v", err)
	}
	if got := writer.writeBuf.String(); got != ConnACK {
		t.Fatalf("WriteACK() payload = %q, want %q", got, ConnACK)
	}
	if writer.firstWriteDeadline.Before(startedWrite.Add(defaultTimeOut - 250*time.Millisecond)) {
		t.Fatalf("WriteACK() first write deadline = %v, want normalized timeout near now+%s", writer.firstWriteDeadline, defaultTimeOut)
	}

	reader := newProtocolDeadlineSpyConn([]byte(ConnACK))
	startedRead := time.Now()
	if err := ReadACK(reader, 0); err != nil {
		t.Fatalf("ReadACK() error = %v", err)
	}
	if reader.firstReadDeadline.Before(startedRead.Add(defaultTimeOut - 250*time.Millisecond)) {
		t.Fatalf("ReadACK() first read deadline = %v, want normalized timeout near now+%s", reader.firstReadDeadline, defaultTimeOut)
	}
}

func TestProtocolHelpersReturnDeadlineErrors(t *testing.T) {
	deadlineErr := errors.New("deadline failed")

	writer := newProtocolDeadlineSpyConn(nil)
	writer.writeDeadlineErr = deadlineErr
	if err := WriteACK(writer, time.Second); !errors.Is(err, deadlineErr) {
		t.Fatalf("WriteACK() error = %v, want %v", err, deadlineErr)
	}
	if got := writer.writeBuf.String(); got != "" {
		t.Fatalf("WriteACK() wrote %q despite deadline error", got)
	}

	reader := newProtocolDeadlineSpyConn([]byte(ConnACK))
	reader.readDeadlineErr = deadlineErr
	if err := ReadACK(reader, time.Second); !errors.Is(err, deadlineErr) {
		t.Fatalf("ReadACK() error = %v, want %v", err, deadlineErr)
	}

	writer = newProtocolDeadlineSpyConn(nil)
	writer.writeDeadlineErr = deadlineErr
	if err := WriteConnectResult(writer, ConnectResultOK, time.Second); !errors.Is(err, deadlineErr) {
		t.Fatalf("WriteConnectResult() error = %v, want %v", err, deadlineErr)
	}

	reader = newProtocolDeadlineSpyConn([]byte{connectResultFrameVersion, byte(ConnectResultOK)})
	reader.readDeadlineErr = deadlineErr
	if _, err := ReadConnectResult(reader, time.Second); !errors.Is(err, deadlineErr) {
		t.Fatalf("ReadConnectResult() error = %v, want %v", err, deadlineErr)
	}
}

func TestProtocolWritersHandleShortWrites(t *testing.T) {
	ackWriter := &chunkedProtocolWriteConn{
		protocolDeadlineSpyConn: newProtocolDeadlineSpyConn(nil),
		maxWrite:                1,
	}
	if err := WriteACK(ackWriter, time.Second); err != nil {
		t.Fatalf("WriteACK() error = %v", err)
	}
	if got := ackWriter.writeBuf.String(); got != ConnACK {
		t.Fatalf("WriteACK() payload = %q, want %q", got, ConnACK)
	}

	resultWriter := &chunkedProtocolWriteConn{
		protocolDeadlineSpyConn: newProtocolDeadlineSpyConn(nil),
		maxWrite:                1,
	}
	if err := WriteConnectResult(resultWriter, ConnectResultNotAllowed, time.Second); err != nil {
		t.Fatalf("WriteConnectResult() error = %v", err)
	}
	want := []byte{connectResultFrameVersion, byte(ConnectResultNotAllowed)}
	if got := resultWriter.writeBuf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("WriteConnectResult() payload = %v, want %v", got, want)
	}
}

func TestConnectResultHelpersNormalizeNonPositiveTimeouts(t *testing.T) {
	writer := newProtocolDeadlineSpyConn(nil)
	startedWrite := time.Now()
	if err := WriteConnectResult(writer, ConnectResultHostUnreachable, 0); err != nil {
		t.Fatalf("WriteConnectResult() error = %v", err)
	}
	if got := writer.writeBuf.Bytes(); !bytes.Equal(got, []byte{connectResultFrameVersion, byte(ConnectResultHostUnreachable)}) {
		t.Fatalf("WriteConnectResult() payload = %v, want %v", got, []byte{connectResultFrameVersion, byte(ConnectResultHostUnreachable)})
	}
	if writer.firstWriteDeadline.Before(startedWrite.Add(defaultTimeOut - 250*time.Millisecond)) {
		t.Fatalf("WriteConnectResult() first write deadline = %v, want normalized timeout near now+%s", writer.firstWriteDeadline, defaultTimeOut)
	}

	reader := newProtocolDeadlineSpyConn([]byte{connectResultFrameVersion, byte(ConnectResultConnectionRefused)})
	startedRead := time.Now()
	status, err := ReadConnectResult(reader, 0)
	if err != nil {
		t.Fatalf("ReadConnectResult() error = %v", err)
	}
	if status != ConnectResultConnectionRefused {
		t.Fatalf("ReadConnectResult() status = %d, want %d", status, ConnectResultConnectionRefused)
	}
	if reader.firstReadDeadline.Before(startedRead.Add(defaultTimeOut - 250*time.Millisecond)) {
		t.Fatalf("ReadConnectResult() first read deadline = %v, want normalized timeout near now+%s", reader.firstReadDeadline, defaultTimeOut)
	}
}
