# AGENTS.md

- Before you finish, `gofmt -l .` must print nothing and `go vet ./...`,
  `go test -race ./...` and the js/wasm tests
  (`GOOS=js GOARCH=wasm go test ./...` with `$(go env GOROOT)/lib/wasm` on
  `PATH`) must pass.
- Standard library only, also for tests. `internal` packages import only the
  standard library; leaf packages never import the root package. Register
  every new package in `deps_test.go`.
- Treat everything from peers and the network as untrusted: bound every read
  and every parse, and reject ambiguous framing instead of guessing.
- Methods on nil connection and listener pointers return `net.ErrClosed`
  instead of panicking.
- User callbacks never run under a lock.
- A handshake that fails closes the connection it was given; plain I/O
  helpers leave it open.
- Tests must not leak goroutines, sockets or timers, and must not rely on OS
  socket buffer sizes.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
