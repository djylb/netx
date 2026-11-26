package netutil

import (
	"net"
	"reflect"
)

// MaxUnwrapDepth bounds external methods that can manufacture a new wrapper on each call.
const MaxUnwrapDepth = 16

// Owned is the ownership description shared with the root package.
type Owned struct {
	Self, First, Second any
	builtin             any // identity of the library wrapper that supplied its actual fields
}

// BuiltinOwned marks the stable children of a library wrapper. Only external
// methods can manufacture a fresh wrapper at every level of a traversal.
func BuiltinOwned(self, first, second any) Owned {
	return Owned{Self: self, First: first, Second: second, builtin: self}
}

// WalkOwned follows only explicit ownership links. The standard TLS connection
// owns its transport but has no ownership method. Recognize its concrete type
// without linking crypto/tls into packages that otherwise do not use it.
func WalkOwned(root any, visit func(any) bool) bool {
	return walk(root, func(v any) (first, second any, external bool) {
		if owner, ok := v.(interface{ NetxOwned() Owned }); ok {
			desc := owner.NetxOwned()
			if Same(desc.Self, v) {
				return desc.First, desc.Second, !Same(desc.builtin, v)
			}
		}
		t := reflect.TypeOf(v)
		if t.Kind() == reflect.Pointer && t.Elem().PkgPath() == "crypto/tls" && t.Elem().Name() == "Conn" {
			child, _ := NextConn(v)
			return child, nil, true
		}
		return nil, nil, false
	}, visit)
}

// Walk visits known layers and follows borrowed NetConn links on other wrappers.
func Walk(root any, children func(any) (any, any, bool), visit func(any) bool) bool {
	return walk(root, func(v any) (any, any, bool) {
		if a, b, ok := children(v); ok {
			return a, b, false
		}
		c, _ := NextConn(v)
		return c, nil, true
	}, visit)
}

func walk(root any, children func(any) (any, any, bool), visit func(any) bool) bool {
	seen := make(map[any]int)
	var descend func(any, int) bool
	descend = func(v any, depth int) bool {
		if v == nil || IsNilPointer(v) {
			return false
		}
		if reflect.ValueOf(v).Comparable() {
			if before, ok := seen[v]; ok && before <= depth {
				return false
			}
			seen[v] = depth
		}
		if visit(v) {
			return true
		}
		a, b, external := children(v)
		if external {
			if depth >= MaxUnwrapDepth {
				return false
			}
			depth++
		}
		return descend(a, depth) || !Same(a, b) && descend(b, depth)
	}
	return descend(root, 0)
}

// NextConn returns the connection that v wraps, if v exposes one.
// The returned connection is borrowed; inspecting it does not transfer ownership.
func NextConn(v any) (net.Conn, bool) {
	getter, ok := v.(interface{ NetConn() net.Conn })
	if !ok {
		return nil, false
	}
	// *tls.Conn.NetConn does not accept a nil receiver.
	if IsNilPointer(getter) {
		return nil, true
	}
	return getter.NetConn(), true
}

// AbortBeneath interrupts the first owned aborter or arms an owned TCP
// connection for a reset. The caller remains responsible for closing the wrapper.
func AbortBeneath(v any, cause error) {
	var tcp *net.TCPConn
	if WalkOwned(v, func(layer any) bool {
		if a, ok := layer.(interface{ Abort(cause error) }); ok {
			a.Abort(cause)
			return true
		}
		if tc, ok := layer.(*net.TCPConn); ok && tcp == nil {
			tcp = tc
		}
		return false
	}) {
		return
	}
	if tcp != nil {
		_ = tcp.SetLinger(0)
	}
}
