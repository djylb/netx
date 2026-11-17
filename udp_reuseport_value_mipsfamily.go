//go:build linux && (mips || mipsle || mips64 || mips64le)

package netx

const soReusePort = 0x200 // SO_REUSEPORT
