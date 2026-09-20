// Package hmacauth implements the shared-secret authentication of the
// core↔search boundary (ADR-002 § "Search service and boundary (Q-001)").
//
// ADR-002 requires the internal endpoints to be "HMAC-verified" without fixing
// the wire format. The wire format is fixed by the canonical contract
// (api/search-internal.openapi.yaml, components.securitySchemes.hmacSignature),
// which vizra-core owns, and by the normative conformance vectors in
// api/search-hmac-testvectors.json. This package implements them; it does not
// define them.
//
// Wire format — three headers, each appearing EXACTLY ONCE:
//
//	X-Vizra-Timestamp: <unix seconds, bare decimal digits>
//	X-Vizra-Nonce:     <16..64 bytes of randomness, lowercase hex>
//	X-Vizra-Signature: v1=<lowercase hex HMAC-SHA256>
//
// Signing string — six fields joined by a single LF, no trailing newline:
//
//	v1 \n METHOD \n request-path \n timestamp \n nonce \n sha256-hex(body)
//
// # Every field enters the canonical string VERBATIM
//
// Nothing here uppercases, trims, reparses or reformats any field. The contract
// is explicit about why: this scheme is implemented twice, and any
// normalisation one side performs and the other does not produces two
// implementations that disagree about which requests are valid. That had
// already happened — one side rebuilt the timestamp through ParseInt→FormatInt,
// so " 1789000000 ", "+1789000000" and "01789000000" verified there and were
// refused here. Non-canonical input is REFUSED, never rewritten.
//
// # The timestamp window actually closes
//
// The timestamp's magnitude is checked against an absolute range
// [MinTimestampUnix, MaxTimestampUnix] BEFORE it is used in any arithmetic, and
// the skew is then computed on plain int64 seconds. Deriving a time value first
// and folding the sign of the difference does NOT close the window:
// time.Time.Sub saturates at math.MinInt64 for a far-future argument, and
// negating math.MinInt64 yields itself, so the comparison silently fails open.
// A validly signed request with a timestamp of 253402300799 was accepted and
// never expired. The absolute range check is what makes that impossible, and
// there is no time.Duration anywhere in this file that is derived from an
// unvalidated header.
//
// A verifier whose OWN clock falls outside the absolute range fails closed, as
// the contract requires.
//
// # Replay
//
// A request is refused when |now - timestamp| exceeds MaxSkew. Inside that
// window an *identical* request can still be replayed, because this service has
// no storage in M0 in which to remember a nonce — PostgreSQL and Redis are both
// out of scope for this slice. The contract states the same limitation ("there
// is no nonce replay store in M0 … A nonce store is required once vizra-search
// owns storage"), so it is recorded here rather than implied to be covered, and
// pinned by TestIdenticalRequestsCanStillBeReplayedInsideTheWindowAtM0.
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

	// MinNonceHexLen is 16 bytes of randomness expressed as lowercase hex, and
	// MaxNonceHexLen is the contract's ceiling of 128 characters.
	MinNonceHexLen = 32
	MaxNonceHexLen = 128

	// MinTimestampUnix (2001-09-09) and MaxTimestampUnix (2100-01-01) are the
	// contract's absolute magnitude bounds. They are checked before any
	// arithmetic, so no saturating subtraction is reachable.
	MinTimestampUnix int64 = 1000000000
	MaxTimestampUnix int64 = 4102444800

	// MaxSignatureHeaderLen bounds the header before it is decoded. "v1=" plus
	// 64 hex characters is the only valid length; a longer value is refused
	// without allocating for it.
	MaxSignatureHeaderLen = 3 + 2*sha256.Size

	// MaxTimestampHeaderLen bounds the digits before they are parsed.
	// MaxTimestampUnix has 10 digits; 20 leaves room to report a too-large
	// value as out of range rather than as malformed.
	MaxTimestampHeaderLen = 20
)

// ErrUnauthorized matches every rejection this package produces.
var ErrUnauthorized = errors.New("hmac authentication failed")

// Reason is a stable, non-sensitive rejection code. It is safe to log: it never
// reveals key material or the expected MAC. It is NOT returned to the caller —
// the contract requires every rejection to be one uniform 401 that does not say
// which rule was broken.
type Reason string

const (
	ReasonNotConfigured      Reason = "not_configured"
	ReasonVerifierClock      Reason = "verifier_clock_out_of_range"
	ReasonMissingSignature   Reason = "missing_signature"
	ReasonMissingTimestamp   Reason = "missing_timestamp"
	ReasonMissingNonce       Reason = "missing_nonce"
	ReasonDuplicateHeader    Reason = "duplicate_header"
	ReasonMalformedMethod    Reason = "malformed_method"
	ReasonMalformedNonce     Reason = "malformed_nonce"
	ReasonMalformedSignature Reason = "malformed_signature"
	ReasonMalformedTimestamp Reason = "malformed_timestamp"
	ReasonTimestampRange     Reason = "timestamp_out_of_range"
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

// SigningString builds the canonical string that is authenticated. Every
// argument is used verbatim.
func SigningString(method, path, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	var b strings.Builder
	b.Grow(len(SignatureVersion) + len(method) + len(path) + len(timestamp) + len(nonce) + 70)
	b.WriteString(SignatureVersion)
	b.WriteByte('\n')
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(timestamp)
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

// isBareDecimalDigits reports whether s matches ^[1-9][0-9]*$ — no sign, no
// leading zero, no whitespace, no separators, no other base.
func isBareDecimalDigits(s string) bool {
	if s == "" || len(s) > MaxTimestampHeaderLen {
		return false
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isLowercaseHexNonce reports whether s is an even-length run of lowercase hex
// between MinNonceHexLen and MaxNonceHexLen characters.
func isLowercaseHexNonce(s string) bool {
	if len(s) < MinNonceHexLen || len(s) > MaxNonceHexLen || len(s)%2 != 0 {
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

// isUppercaseASCIIMethod reports whether s is one or more uppercase ASCII
// letters. The contract rejects a lowercase method rather than uppercasing it.
func isUppercaseASCIIMethod(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// isLowercaseHexMAC reports whether s is exactly 2*sha256.Size lowercase hex
// characters. hex.DecodeString accepts uppercase, and the contract requires
// lowercase, so the case is checked explicitly.
func isLowercaseHexMAC(s string) bool {
	if len(s) != 2*sha256.Size {
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

// Sign returns the signature header value for a request. Every field is signed
// verbatim, so a caller that passes a non-canonical field produces a signature
// this package's own Verify will refuse — which is the point: the signer and
// the verifier agree on one set of bytes.
func Sign(key []byte, method, path, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(SigningString(method, path, timestamp, nonce, body)))
	return SignatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}

// SignAt returns the timestamp and signature header values for a request at a
// given time, generating nothing implicitly except the timestamp's decimal
// rendering, which strconv.FormatInt already produces in canonical form.
func SignAt(key []byte, method, path string, at time.Time, nonce string, body []byte) (timestampHeader, signatureHeader string) {
	ts := strconv.FormatInt(at.Unix(), 10)
	return ts, Sign(key, method, path, ts, nonce, body)
}

// SignRequest sets all three headers on a request, generating a fresh nonce.
// It is the only supported way to sign, so a caller cannot forget the nonce.
func SignRequest(key []byte, req *http.Request, body []byte) error {
	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	ts, sig := SignAt(key, req.Method, req.URL.EscapedPath(), time.Now(), nonce, body)
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

// exactlyOnce returns the single value of a header, or false when the header is
// absent or appears more than once. A duplicated header is ambiguous — one
// implementation reads the first value, another the last — so the contract
// requires it to be rejected rather than resolved.
func exactlyOnce(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// Verify authenticates a request. The method and path must be exactly the bytes
// the peer signed, and body must be the exact bytes the handler will read.
func (v *Verifier) Verify(method, path string, header http.Header, body []byte) error {
	// Fail closed on an unconfigured verifier rather than accepting anything.
	if len(v.Key) == 0 || v.MaxSkew <= 0 {
		return reject(ReasonNotConfigured)
	}

	// The verifier's own clock must be sane, or "within 300 s of now" means
	// nothing. The contract requires this to fail closed.
	nowUnix := v.now().Unix()
	if nowUnix < MinTimestampUnix || nowUnix > MaxTimestampUnix {
		return reject(ReasonVerifierClock)
	}

	// Each header exactly once. Absent and duplicated are distinguished for the
	// log only; both are the same 401 to the caller.
	rawSig, ok := exactlyOnce(header, HeaderSignature)
	if !ok {
		if len(header.Values(HeaderSignature)) > 1 {
			return reject(ReasonDuplicateHeader)
		}
		return reject(ReasonMissingSignature)
	}
	rawTS, ok := exactlyOnce(header, HeaderTimestamp)
	if !ok {
		if len(header.Values(HeaderTimestamp)) > 1 {
			return reject(ReasonDuplicateHeader)
		}
		return reject(ReasonMissingTimestamp)
	}
	nonce, ok := exactlyOnce(header, HeaderNonce)
	if !ok {
		if len(header.Values(HeaderNonce)) > 1 {
			return reject(ReasonDuplicateHeader)
		}
		return reject(ReasonMissingNonce)
	}

	// The method is used exactly as sent and must already be uppercase.
	if !isUppercaseASCIIMethod(method) {
		return reject(ReasonMalformedMethod)
	}

	// The nonce is used exactly as sent and must be lowercase hex in range.
	if !isLowercaseHexNonce(nonce) {
		return reject(ReasonMalformedNonce)
	}

	// The signature header is bounded, then shape-checked, then decoded.
	if len(rawSig) > MaxSignatureHeaderLen {
		return reject(ReasonMalformedSignature)
	}
	prefix := SignatureVersion + "="
	if !strings.HasPrefix(rawSig, prefix) {
		return reject(ReasonMalformedSignature)
	}
	macHex := rawSig[len(prefix):]
	if !isLowercaseHexMAC(macHex) {
		return reject(ReasonMalformedSignature)
	}
	provided, err := hex.DecodeString(macHex)
	if err != nil {
		return reject(ReasonMalformedSignature)
	}

	// The timestamp is shape-checked as bare decimal digits, then its MAGNITUDE
	// is checked against the absolute range, and only then is it parsed into a
	// number used in arithmetic. Nothing below constructs a time.Duration from
	// it, so the saturating-subtraction failure is unreachable by construction.
	if !isBareDecimalDigits(rawTS) {
		return reject(ReasonMalformedTimestamp)
	}
	unixSeconds, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		// Unreachable for a shape-checked value of at most 20 digits only when
		// it also fits in an int64; a 20-digit value can overflow, and that is
		// an out-of-range timestamp, not a malformed one.
		return reject(ReasonTimestampRange)
	}
	if unixSeconds < MinTimestampUnix || unixSeconds > MaxTimestampUnix {
		return reject(ReasonTimestampRange)
	}

	// Plain int64 seconds. Both operands are now known to lie within
	// [1000000000, 4102444800], so the subtraction cannot overflow or saturate.
	skewSeconds := nowUnix - unixSeconds
	if skewSeconds < 0 {
		skewSeconds = -skewSeconds
	}
	maxSkewSeconds := int64(v.MaxSkew / time.Second)
	if skewSeconds > maxSkewSeconds {
		return reject(ReasonStaleTimestamp)
	}

	// Every field goes into the canonical string exactly as it arrived.
	mac := hmac.New(sha256.New, v.Key)
	mac.Write([]byte(SigningString(method, path, rawTS, nonce, body)))
	expected := mac.Sum(nil)

	// Constant-time comparison: hmac.Equal does not short-circuit on the first
	// differing byte, so the rejection time carries no information about how
	// much of the MAC the caller guessed correctly.
	if !hmac.Equal(provided, expected) {
		return reject(ReasonBadSignature)
	}
	return nil
}
