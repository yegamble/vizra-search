package httpapi

import (
	"bytes"
	"context"
	"io"
	"time"
)

// contextWithTimeout is a thin wrapper so the deadline policy lives in one
// place and the server file does not import context directly.
func contextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}

// newByteReader wraps already-buffered bytes for a decoder.
func newByteReader(b []byte) io.Reader { return bytes.NewReader(b) }
