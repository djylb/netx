//go:build linux && !(mips || mipsle || mips64 || mips64le)

package udpflow

const soReusePort = 0xf // SO_REUSEPORT
