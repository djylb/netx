package netx

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestPackageDependencies enforces the module's dependency boundaries and
// checks which packages bring in crypto/tls.
func TestPackageDependencies(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("cannot run the go command")
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	const module = "github.com/djylb/netx"
	const timeshim = "github.com/djylb/timeshim"
	type pkgRule struct {
		pkg  string
		tls  bool
		leaf bool // the standard library and internal packages only
	}
	rules := []pkgRule{
		{module, false, false},
		{module + "/duplex", false, true},
		{module + "/proxyproto", false, true},
		{module + "/transparent", false, true},
		{module + "/udpflow", false, true},
		{module + "/socks5", false, false},
		{module + "/httpproxy", false, false},
		{module + "/httphead", false, true},
		{module + "/tlsconn", true, true},
		{module + "/proxydial", false, false},
		{module + "/forwarded", false, true},
		{module + "/httprewrite", true, false}, // net/http links crypto/tls
		{module + "/wsconn", false, false},     // httphead; wsconn/deps_test.go checks the rest
		{module + "/wsconn/wshttp", true, false},
		{module + "/safedial", false, false},
		{module + "/memnet", false, true},
	}
	const internalPrefix = module + "/internal/"
	allowedInternal := map[string][]string{
		internalPrefix + "dgram":     {internalPrefix + "clock", internalPrefix + "bufpool"},
		internalPrefix + "dnslookup": {internalPrefix + "bufpool"},
		internalPrefix + "flowtable": {internalPrefix + "dgram", internalPrefix + "clock", internalPrefix + "bufpool"},
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
			case path == timeshim:
				// The injectable clock, of the standard library alone, which
				// every package may use.
			case path == "crypto/tls" && !tt.tls:
				t.Errorf("%s links crypto/tls", tt.pkg)
			case path == module || strings.HasPrefix(path, module+"/"):
				if tt.leaf && !strings.HasPrefix(path, internalPrefix) ||
					strings.HasPrefix(tt.pkg, internalPrefix) && !slices.Contains(allowedInternal[tt.pkg], path) {
					t.Errorf("%s depends on %s", tt.pkg, path)
				}
			case std != "true":
				t.Errorf("%s depends on %s outside the standard library", tt.pkg, path)
			}
		}
	}
}
