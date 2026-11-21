// Package memnet is an in-process network for tests: stream listeners and
// connections that behave like TCP sockets (buffered in both directions,
// half-close, reset on SetLinger(0), deadlines), packet endpoints that
// deliver whole datagrams and drop them when full, a resolver, dials from a
// chosen source host, and fault injection per address and direction:
// delay, rate, loss and cut links, driven by an injectable clock and
// randomness source.
//
// It also holds LoopbackUDP, a real UDP socket bound so that its replies
// cannot be lost to another socket on the same port.
package memnet
