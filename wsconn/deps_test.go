package wsconn

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestDependencies checks what the package documentation promises: wsconn
// links neither net/http nor crypto/tls, nor the crypto packages whose
// FIPS machinery would make a program larger, and of this module only
// httphead and internal packages, not the root package; wshttp adds
// net/http and wsconn.
func TestDependencies(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("cannot run the go command")
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	const module = "github.com/djylb/netx"
	rules := []struct {
		pkg       string
		forbidden []string
		allowed   []string // packages of this module
	}{
		{module + "/wsconn", []string{"net/http", "crypto/tls", "crypto/sha1", "crypto/rand"}, []string{module + "/httphead"}},
		{module + "/wsconn/wshttp", nil, []string{module + "/httphead", module + "/wsconn"}},
	}
	for _, r := range rules {
		out, err := exec.Command(goCmd, "list", "-deps", "-f", "{{.ImportPath}}", r.pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", r.pkg, err)
		}
		for line := range strings.Lines(string(out)) {
			path := strings.TrimSpace(line)
			switch {
			case path == r.pkg:
			case strings.HasPrefix(path, module+"/internal/"):
			case path == module || strings.HasPrefix(path, module+"/"):
				if !slices.Contains(r.allowed, path) {
					t.Errorf("%s depends on %s", r.pkg, path)
				}
			case slices.Contains(r.forbidden, path):
				t.Errorf("%s links %s", r.pkg, path)
			}
		}
	}
}
