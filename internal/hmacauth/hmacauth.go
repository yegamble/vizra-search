// Package hmacauth implements the shared-secret authentication of the
// core↔search boundary (ADR-002 § "Search service and boundary (Q-001)").
//
// ADR-002 requires the internal endpoints to be "HMAC-verified" without fixing
// the wire format. The wire format is fixed by the canonical contract
// (api/search-internal.openapi.yaml, components.securitySchemes.hmacSignature),
// which vizra-core owns. This package implements it; it does not define it.
//
// Wire format — three headers:
//
//	X-Vizra-Timestamp: <unix seconds, decimal digits>
//	X-Vizra-Nonce:     <at least 16 bytes of randomness, lowercase hex>
//	X-Vizra-Signature: v1=<lowercase hex HMAC-SHA256>
//
// Signing string — six fields joined by a single LF, no trailing newline:
//
//	v1 \n METHOD \n request-path \n timestamp \n nonce \n sha256-hex(body)
//
// Binding the method, the path, the nonce and a digest of the exact body into
// the MAC means a captured signature cannot be moved to another endpoint,
// another verb or another payload.
//
// Replay: a request is refused when |now - timestamp| exceeds MaxSkew. Inside
// that window an *identical* request can still be replayed, because this
// service has no storage in M0 in which to remember a nonce — PostgreSQL and
// Redis are both out of scope for this slice. The contract states the same
// limitation ("Nonce replay rejection is required once search owns storage;
// until then the timestamp window is the only replay bound"), so it is recorded
// here rather than implied to be covered.
package hmacauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names and the signature version prefix.
const (
	HeaderTimestamp  = "X-Vizra-Timestamp"
	HeaderNonce      = "X-Vizra-Nonce"
	HeaderSignature  = "X-Vizra-Signature"
	SignatureVersion = "v1"

	// MinNonceHexLen is 16 bytes of randomness expressed as lowercase hex, the
	// contract's minimum.
	MinNonceHexLen = 32
)

// ErrUnauthorized matches every rejection this package produces.
var ErrUnauthorized = errors.New("hmac authentication failed")

// Reason is a stable, non-sensitive rejection code. It is safe to log and safe
// to return to the caller: it never reveals key material or the expected MAC.
type Reason string

const (
	ReasonNotConfigured      Reason = "not_configured"
	ReasonMissingSignature   Reason = "missing_signature"
	ReasonMissingTimestamp   Reason = "missing_timestamp"
	ReasonMissingNonce       Reason = "missing_nonce"
	ReasonMalformedNonce     Reason = "malformed_nonce"
	ReasonMalformedSignature Reason = "malformed_signature"
	ReasonMalformedTimestamp Reason = "malformed_timestamp"
	ReasonStaleTimestamp     Reason = "stale_timestamp"
	ReasonBadSignature       Reason = "bad_signature"
)

// Error is the typed rejection.
type Error struct {
	Reason Reason
}

func (e *Error) Error() string { return fmt.Sprintf("hmac authentication failed: %s", e.Reason) }

// Is makes errors.Is(err, ErrUnauthorized) true for every rejection.
func (e *Error) Is(target error) bool { return target == ErrUnauthorized }

func reject(r Reason) error { return &Error{Reason: r} }

// SigningString builds the canonical string that is authenticated.
func SigningString(method, path string, unixSeconds int64, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	var b strings.Builder
	b.Grow(len(SignatureVersion) + len(method) + len(path) + len(nonce) + 96)
	b.WriteString(SignatureVersion)
	b.WriteByte('\n')
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(unixSeconds, 10))
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return b.String()
}

// NewNonce returns a fresh nonce: 16 cryptographically random bytes as
// lowercase hex, the contract's minimum.
func NewNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generating a nonce: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// validNonce reports whether s is at least 16 bytes of lowercase hex.
func validNonce(s string) bool {
	if len(s) < MinNonceHexLen || len(s)%2 != 0 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Sign returns the timestamp and signature header values for a request. It is
// exported because the tests, and any future client in this repository, must
// produce signatures with exactly the code that verifies them.
func Sign(key []byte, method, path string, at time.Time, nonce string, body []byte) (timestampHeader, signatureHeader string) {
	ts := at.Unix()
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(SigningString(method, path, ts, nonce, body)))
	return strconv.FormatInt(ts, 10), SignatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}

// SignRequest sets all three headers on a request, generating a fresh nonce.
// It is the only supported way to sign, so a caller cannot forget the nonce.
func SignRequest(key []byte, req *http.Request, body []byte) error {
	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	ts, sig := Sign(key, req.Method, req.URL.Path, time.Now(), nonce, body)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, sig)
	return nil
}

// Verifier verifies inbound requests against a shared secret.
type Verifier struct {
	// Key is the shared secret. An empty Key fails every request closed.
	Key []byte
	// MaxSkew bounds how far a request timestamp may be from Now in either
	// direction. A non-positive MaxSkew fails every request closed.
	MaxSkew time.Duration
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify authenticates a request. body must be the exact bytes the handler
// will read.
func (v *Verifier) Verify(method, path string, header http.Header, body []byte) error {
	// Fail closed on an unconfigured verifier rather than accepting anything.
	if len(v.Key) == 0 || v.MaxSkew <= 0 {
		return reject(ReasonNotConfigured)
	}

	rawSig := strings.TrimSpace(header.Get(HeaderSignature))
	if rawSig == "" {
		return reject(ReasonMissingSignature)
	}
	rawTS := strings.TrimSpace(header.Get(HeaderTimestamp))
	if rawTS == "" {
		return reject(ReasonMissingTimestamp)
	}
	nonce := strings.TrimSpace(header.Get(HeaderNonce))
	if nonce == "" {
		return reject(ReasonMissingNonce)
	}
	if !validNonce(nonce) {
		return reject(ReasonMalformedNonce)
	}

	prefix := SignatureVersion + "="
	if !strings.HasPrefix(rawSig, prefix) {
		return reject(ReasonMalformedSignature)
	}
	provided, err := hex.DecodeString(rawSig[len(prefix):])
	if err != nil || len(provided) != sha256.Size {
		return reject(ReasonMalformedSignature)
	}

	unixSeconds, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return reject(ReasonMalformedTimestamp)
	}

	// The timestamp is checked before the MAC so that a stale-but-valid
	// signature is reported as stale rather than as a bad signature. Both
	// outcomes are a refusal, so this ordering leaks nothing an attacker could
	// not already determine from their own clock.
	skew := v.now().Sub(time.Unix(unixSeconds, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > v.MaxSkew {
		return reject(ReasonStaleTimestamp)
	}

	mac := hmac.New(sha256.New, v.Key)
	mac.Write([]byte(SigningString(method, path, unixSeconds, nonce, body)))
	expected := mac.Sum(nil)

	// Constant-time comparison: hmac.Equal does not short-circuit on the first
	// differing byte, so the rejection time carries no information about how
	// much of the MAC the caller guessed correctly.
	if !hmac.Equal(provided, expected) {
		return reject(ReasonBadSignature)
	}
	return nil
}
