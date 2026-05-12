package netx

import (
	"errors"
	"net"
	"strings"
	"time"
)

const DefaultTimeout = 5 * time.Second

const defaultTimeOut = DefaultTimeout

func normalizeLinkTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultTimeout
	}
	return timeout
}

func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	s := strings.ToLower(strings.ReplaceAll(err.Error(), " ", ""))
	return strings.Contains(s, "timeout")
}
