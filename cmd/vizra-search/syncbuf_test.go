package main_test

import (
	"bytes"
	"sync"
)

// syncBuffer is a bytes.Buffer safe for concurrent use. exec.Cmd copies a
// process's output on its own goroutine when Stdout is not an *os.File, so a
// test that reads the captured output while the process is still running needs
// this; a plain bytes.Buffer is a data race the race detector will catch.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
