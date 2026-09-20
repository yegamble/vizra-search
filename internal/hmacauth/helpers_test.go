package hmacauth_test

import (
	"bytes"
	"crypto/sha256"
	"io"
)

func newReader(b []byte) io.Reader { return bytes.NewReader(b) }

func sha256Sum(b []byte) [sha256.Size]byte { return sha256.Sum256(b) }
