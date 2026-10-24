package netx

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestPackageDependencies checks what the README promises: every package
// depends on the standard library and this module alone, crypto/tls is
// linked only by tlsconn, proxydial, and httprewrite and wsconn/wshttp
// through net/http, and forwarded, httphead, proxyproto, tlsconn and
// transparent depend on the standard library and this module's internal
// packages alone, which depend on the standard library alone.
func TestPackageDependencies(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("cannot run the go command")
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	const module = "github.com/djylb/netx"
	type pkgRule struct {
		pkg  string
		tls  bool
		leaf bool // the standard library and internal packages only
	}
	rules := []pkgRule{
		{module, false, false},
		{module + "/proxyproto", false, true},
		{module + "/transparent", false, true},
		{module + "/socks5", false, false},
		{module + "/httpproxy", false, false},
		{module + "/httphead", false, true},
		{module + "/tlsconn", true, true},
		{module + "/proxydial", true, false},
		{module + "/forwarded", false, true},
		{module + "/httprewrite", true, false}, // net/http links crypto/tls
		{module + "/wsconn", false, false},     // httphead; wsconn/deps_test.go checks the rest
		{module + "/wsconn/wshttp", true, false},
		{module + "/safedial", false, false},
	}
	internal, err := exec.Command(goCmd, "list", module+"/internal/...").Output()
	if err != nil {
		t.Fatalf("go list internal: %v", err)
	}
	for line := range strings.Lines(string(internal)) {
		rules = append(rules, pkgRule{pkg: strings.TrimSpace(line), leaf: true})
	}
	for _, tt := range rules {
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
				internal := strings.HasPrefix(path, module+"/internal/")
				if tt.leaf && (!internal || strings.HasPrefix(tt.pkg, module+"/internal/")) {
					t.Errorf("%s depends on %s", tt.pkg, path)
				}
			case std != "true":
				t.Errorf("%s depends on %s outside the standard library", tt.pkg, path)
			}
		}
	}
}
