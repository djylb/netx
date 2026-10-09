//go:build darwin

package transparent

import (
	"context"
	"testing"
)

func TestListenOnDarwin(t *testing.T) {
	ln, err := Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	assertAccepts(t, ln)
}
