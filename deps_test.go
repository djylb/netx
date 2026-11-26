package netx

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
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
		{module + "/internal/bufpool", false, true},
		{module + "/internal/clock", false, true},
		{module + "/internal/creds", false, true},
		{module + "/internal/dgram", false, true},
		{module + "/internal/dnslookup", false, true},
		{module + "/internal/flowtable", false, true},
		{module + "/internal/leakcheck", false, true},
		{module + "/internal/nettest", false, true},
		{module + "/internal/netutil", false, true},
		{module + "/internal/serve", false, true},
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
		internalPrefix + "flowtable": {internalPrefix + "dgram", internalPrefix + "clock"},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, goCmd, "list", "-mod=readonly", "-buildvcs=false", "-deps", "-test", "-json=ImportPath,Standard,Imports,Deps,TestImports,XTestImports,ForTest", "./...").Output()
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json matches the Go command's field names case-insensitively.
	type pkg struct {
		ImportPath   string   `json:"importPath"`
		ForTest      string   `json:"forTest"`
		Standard     bool     `json:"standard"`
		Imports      []string `json:"imports"`
		Deps         []string `json:"deps"`
		TestImports  []string `json:"testImports"`
		XTestImports []string `json:"xTestImports"`
	}
	pkgs := make(map[string]pkg)
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		if p.ForTest != "" || strings.HasSuffix(p.ImportPath, ".test") || strings.Contains(p.ImportPath, " [") {
			continue
		}
		pkgs[p.ImportPath] = p
	}
	registered := make(map[string]pkgRule)
	for _, rule := range rules {
		registered[rule.pkg] = rule
	}
	for path, p := range pkgs {
		if p.Standard || path == "C" || path == timeshim {
			continue
		}
		if path != module && !strings.HasPrefix(path, module+"/") {
			t.Errorf("unapproved dependency %s", path)
			continue
		}
		rule, ok := registered[path]
		internal := strings.HasPrefix(path, internalPrefix)
		if !ok {
			t.Errorf("unregistered package %s", path)
		}
		delete(registered, path)
		for _, dep := range p.Deps {
			if dep == "crypto/tls" && !rule.tls {
				t.Errorf("%s links %s", path, dep)
			}
			if rule.leaf && (dep == module || strings.HasPrefix(dep, module+"/") && !strings.HasPrefix(dep, internalPrefix)) {
				t.Errorf("%s depends on %s", path, dep)
			}
		}
		for _, dep := range p.Imports {
			if internal && (dep == module || strings.HasPrefix(dep, module+"/")) && !slices.Contains(allowedInternal[path], dep) {
				t.Errorf("%s directly imports %s", path, dep)
			}
		}
		for _, imports := range [][]string{p.TestImports, p.XTestImports} {
			for _, dep := range imports {
				if pkgs[dep].Standard || dep == timeshim || dep == path {
					continue
				}
				if dep != module && !strings.HasPrefix(dep, module+"/") {
					t.Errorf("%s tests import %s", path, dep)
				}
				if internal && dep != internalPrefix+"leakcheck" && !slices.Contains(allowedInternal[path], dep) {
					t.Errorf("%s tests import %s", path, dep)
				}
			}
		}
	}
	for path := range registered {
		t.Errorf("registered package missing: %s", path)
	}
}
