package safedial

import (
	"testing"

	"github.com/djylb/netx/internal/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.VerifyTestMain(m) }
