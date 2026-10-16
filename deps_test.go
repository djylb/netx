package netx

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestPackageDependencies checks what the README promises: every package
// depends on the standard library and this module alone, crypto/tls is
// linked only by tlsconn and proxy, and proxyproto and tlsconn depend on the
// standard library alone.
func TestPackageDependencies(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("cannot run the go command")
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	const module = "github.com/djylb/netx"
	for _, tt := range []struct {
		pkg  string
		tls  bool
		leaf bool // the standard library only
	}{
		{module, false, false},
		{module + "/proxyproto", false, true},
		{module + "/transparent", false, false},
		{module + "/socks5", false, false},
		{module + "/tlsconn", true, true},
		{module + "/proxy", true, false},
	} {
		out, err := exec.Command(goCmd, "list", "-deps", "-f", "{{.ImportPath}} {{.Standard}}", tt.pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", tt.pkg, err)
		}
		for line := range strings.Lines(string(out)) {
			path, std, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch {
			case path == tt.pkg:
			case path == "crypto/tls" && !tt.tls:
				t.Errorf("%s links crypto/tls", tt.pkg)
			case path == module || strings.HasPrefix(path, module+"/"):
				if tt.leaf {
					t.Errorf("%s depends on %s", tt.pkg, path)
				}
			case std != "true":
				t.Errorf("%s depends on %s outside the standard library", tt.pkg, path)
			}
		}
	}
}
