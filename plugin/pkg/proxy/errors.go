package proxy

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNoHealthy means no healthy proxies left.
	ErrNoHealthy = errors.New("no healthy proxies")
	// ErrNoForward means no forwarder defined.
	ErrNoForward = errors.New("no forwarder defined")
	// ErrCachedClosed means cached connection was closed by peer.
	ErrCachedClosed = errors.New("cached connection was closed by peer")
	// ErrUnsupportedRequest means the proxy transport cannot represent the request.
	ErrUnsupportedRequest = errors.New("proxy: unsupported request")
	// ErrSetup marks failures that happen before the query is handed to the
	// upstream: dialing, TLS/QUIC handshakes and taking a connection from the
	// cache. A setup failure is safe to retry on a fresh connection; a failure
	// after the query was written must not be retried against the same upstream.
	ErrSetup = errors.New("proxy: connection setup failed")
)

// SetupError wraps err as a connection-setup failure.
func SetupError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrSetup, err)
}

// Options holds various Options that can be set.
type Options struct {
	// ForceTCP use TCP protocol for upstream DNS request. Has precedence over PreferUDP flag
	ForceTCP bool
	// PreferUDP use UDP protocol for upstream DNS request.
	PreferUDP bool
	// HCRecursionDesired sets recursion desired flag for Proxy healthcheck requests
	HCRecursionDesired bool
	// HCDomain sets domain for Proxy healthcheck requests
	HCDomain string
	// TLSConnectDeadline bounds the TCP dial and TLS handshake for DoT, not the DNS exchange.
	// A zero value leaves the adaptive dial timeout and caller context as the only limits.
	TLSConnectDeadline time.Time
}
