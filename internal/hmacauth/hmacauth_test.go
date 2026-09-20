package hmacauth_test

import (
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/hmacauth"
)

var (
	key      = []byte("9f2c1d7a4b3e6f80c5a91d2e3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b")
	otherKey = []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
)

const (
	method = http.MethodPost
	path   = "/internal/v1/search"
)

var body = []byte(`{"query":"sunset","limit":20}`)

func fixedNow() time.Time { return time.Unix(1_774_000_000, 0).UTC() }

func newVerifier() *hmacauth.Verifier {
	return &hmacauth.Verifier{Key: key, MaxSkew: 300 * time.Second, Now: fixedNow}
}

const testNonce = "0123456789abcdef0123456789abcdef"

func signedHeader(t *testing.T, k []byte, at time.Time, m, p string, b []byte) http.Header {
	t.Helper()
	h := http.Header{}
	ts, sig := hmacauth.SignAt(k, m, p, at, testNonce, b)
	h.Set(hmacauth.HeaderTimestamp, ts)
	h.Set(hmacauth.HeaderNonce, testNonce)
	h.Set(hmacauth.HeaderSignature, sig)
	return h
}

func wantReason(t *testing.T, err error, reason hmacauth.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rejection with reason %q, got nil", reason)
	}
	var authErr *hmacauth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("error %v is not *hmacauth.Error", err)
	}
	if authErr.Reason != reason {
		t.Fatalf("reason = %q, want %q", authErr.Reason, reason)
	}
	if !errors.Is(err, hmacauth.ErrUnauthorized) {
		t.Fatalf("error %v does not match ErrUnauthorized", err)
	}
}

func TestVerifyAcceptsACorrectlySignedRequest(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	if err := v.Verify(method, path, h, body); err != nil {
		t.Fatalf("Verify rejected a correctly signed request: %v", err)
	}
}

// A1 of the brief's negative set: no signature header at all.
func TestVerifyRejectsAMissingSignature(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	h.Del(hmacauth.HeaderSignature)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonMissingSignature)
}

func TestVerifyRejectsAMissingTimestamp(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	h.Del(hmacauth.HeaderTimestamp)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonMissingTimestamp)
}

func TestVerifyRejectsAnEmptyHeaderSet(t *testing.T) {
	v := newVerifier()
	wantReason(t, v.Verify(method, path, http.Header{}, body), hmacauth.ReasonMissingSignature)
}

// A2: a signature produced with a different key.
func TestVerifyRejectsAWrongSignature(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, otherKey, fixedNow(), method, path, body)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonBadSignature)
}

func TestVerifyRejectsAMalformedSignature(t *testing.T) {
	v := newVerifier()
	for _, bad := range []string{
		"",
		"deadbeef",                      // no version prefix
		"v1=",                           // empty mac
		"v1=zzzz",                       // not hex
		"v2=" + strings.Repeat("a", 64), // unknown version
		"v1=" + strings.Repeat("a", 62), // wrong length
	} {
		h := signedHeader(t, key, fixedNow(), method, path, body)
		h.Set(hmacauth.HeaderSignature, bad)
		err := v.Verify(method, path, h, body)
		if err == nil {
			t.Fatalf("Verify accepted malformed signature %q", bad)
		}
		var authErr *hmacauth.Error
		if !errors.As(err, &authErr) {
			t.Fatalf("error for %q is not *hmacauth.Error: %v", bad, err)
		}
		if authErr.Reason != hmacauth.ReasonMalformedSignature && authErr.Reason != hmacauth.ReasonMissingSignature {
			t.Fatalf("reason for %q = %q", bad, authErr.Reason)
		}
	}
}

// A3: a timestamp outside the replay window, in both directions.
func TestVerifyRejectsAStaleTimestamp(t *testing.T) {
	v := newVerifier()
	past := fixedNow().Add(-301 * time.Second)
	wantReason(t, v.Verify(method, path, signedHeader(t, key, past, method, path, body), body), hmacauth.ReasonStaleTimestamp)
}

func TestVerifyRejectsAFutureTimestamp(t *testing.T) {
	v := newVerifier()
	future := fixedNow().Add(301 * time.Second)
	wantReason(t, v.Verify(method, path, signedHeader(t, key, future, method, path, body), body), hmacauth.ReasonStaleTimestamp)
}

func TestVerifyAcceptsTimestampsInsideTheWindow(t *testing.T) {
	v := newVerifier()
	for _, offset := range []time.Duration{-299 * time.Second, -1 * time.Second, 0, 299 * time.Second} {
		at := fixedNow().Add(offset)
		if err := v.Verify(method, path, signedHeader(t, key, at, method, path, body), body); err != nil {
			t.Fatalf("Verify rejected offset %v: %v", offset, err)
		}
	}
}

func TestVerifyRejectsAMalformedTimestamp(t *testing.T) {
	v := newVerifier()
	for _, bad := range []string{"", "not-a-number", "1774000000.5", "0x1", " "} {
		h := signedHeader(t, key, fixedNow(), method, path, body)
		h.Set(hmacauth.HeaderTimestamp, bad)
		err := v.Verify(method, path, h, body)
		if err == nil {
			t.Fatalf("Verify accepted timestamp %q", bad)
		}
		var authErr *hmacauth.Error
		if !errors.As(err, &authErr) {
			t.Fatalf("error for %q is not *hmacauth.Error", bad)
		}
		if authErr.Reason != hmacauth.ReasonMalformedTimestamp && authErr.Reason != hmacauth.ReasonMissingTimestamp {
			t.Fatalf("reason for timestamp %q = %q", bad, authErr.Reason)
		}
	}
}

// A4: the body is bound into the signature, so a modified body fails even
// though the signature and timestamp are otherwise valid and fresh.
func TestVerifyRejectsATamperedBody(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	tampered := []byte(`{"query":"sunset","limit":2000}`)
	wantReason(t, v.Verify(method, path, h, tampered), hmacauth.ReasonBadSignature)
}

func TestVerifyRejectsATruncatedBody(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	wantReason(t, v.Verify(method, path, h, body[:len(body)-1]), hmacauth.ReasonBadSignature)
}

// The method and the path are bound in too, so a signature captured for one
// endpoint cannot be replayed against another.
func TestVerifyRejectsACrossEndpointReplay(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, "/internal/v1/search", body)
	wantReason(t, v.Verify(method, "/internal/v1/events", h, body), hmacauth.ReasonBadSignature)
}

func TestVerifyRejectsAMethodSwap(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), http.MethodPost, path, body)
	wantReason(t, v.Verify(http.MethodGet, path, h, body), hmacauth.ReasonBadSignature)
}

func TestVerifyWithoutAKeyFailsClosed(t *testing.T) {
	v := &hmacauth.Verifier{Key: nil, MaxSkew: time.Minute, Now: fixedNow}
	h := signedHeader(t, key, fixedNow(), method, path, body)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonNotConfigured)
}

func TestVerifyWithoutASkewBoundFailsClosed(t *testing.T) {
	v := &hmacauth.Verifier{Key: key, MaxSkew: 0, Now: fixedNow}
	h := signedHeader(t, key, fixedNow(), method, path, body)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonNotConfigured)
}

func TestSigningStringIsCanonicalAndStable(t *testing.T) {
	got := hmacauth.SigningString(method, path, "1774000000", testNonce, body)
	want := "v1\nPOST\n/internal/v1/search\n1774000000\n" + testNonce + "\n" +
		"953d56a8c08e56f71709a941aea7139242b258b05fbd25bd9c5b7d965294dab9"
	if got != want {
		t.Fatalf("SigningString =\n%q\nwant\n%q", got, want)
	}
}

func TestEmptyBodyHashesAsTheEmptyString(t *testing.T) {
	v := newVerifier()
	for _, b := range [][]byte{nil, {}} {
		h := signedHeader(t, key, fixedNow(), http.MethodGet, "/internal/v1/search", b)
		if err := v.Verify(http.MethodGet, "/internal/v1/search", h, b); err != nil {
			t.Fatalf("Verify rejected an empty body: %v", err)
		}
	}
}

func TestErrorNeverLeaksTheExpectedSignature(t *testing.T) {
	// ADR-002 § Logging and redaction: a rejection must not hand an attacker
	// the value they failed to produce.
	v := newVerifier()
	h := signedHeader(t, otherKey, fixedNow(), method, path, body)
	err := v.Verify(method, path, h, body)
	_, expected := hmacauth.SignAt(key, method, path, fixedNow(), testNonce, body)
	if strings.Contains(err.Error(), strings.TrimPrefix(expected, "v1=")) {
		t.Fatalf("rejection leaks the expected MAC: %v", err)
	}
	if strings.Contains(err.Error(), string(key)) {
		t.Fatalf("rejection leaks the key: %v", err)
	}
}

func TestSignIsDeterministic(t *testing.T) {
	ts1, sig1 := hmacauth.SignAt(key, method, path, fixedNow(), testNonce, body)
	ts2, sig2 := hmacauth.SignAt(key, method, path, fixedNow(), testNonce, body)
	if ts1 != ts2 || sig1 != sig2 {
		t.Fatalf("Sign is not deterministic: (%s,%s) vs (%s,%s)", ts1, sig1, ts2, sig2)
	}
	if !strings.HasPrefix(sig1, "v1=") {
		t.Fatalf("signature %q lacks the version prefix", sig1)
	}
	if len(sig1) != len("v1=")+64 {
		t.Fatalf("signature %q is not 32 hex-encoded bytes", sig1)
	}
}

// The nonce is part of the canonical string, so the three headers must agree.
func TestVerifyRejectsAMissingNonce(t *testing.T) {
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	h.Del(hmacauth.HeaderNonce)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonMissingNonce)
}

func TestVerifyRejectsAMalformedNonce(t *testing.T) {
	v := newVerifier()
	for _, bad := range []string{
		"short",
		"0123456789abcdef",                 // 8 bytes, below the 16-byte minimum
		"0123456789ABCDEF0123456789ABCDEF", // uppercase is not lowercase hex
		"0123456789abcdef0123456789abcdeg", // not hex
		strings.Repeat("a", 31),            // odd length
	} {
		h := signedHeader(t, key, fixedNow(), method, path, body)
		h.Set(hmacauth.HeaderNonce, bad)
		err := v.Verify(method, path, h, body)
		if err == nil {
			t.Fatalf("Verify accepted nonce %q", bad)
		}
		var authErr *hmacauth.Error
		if !errors.As(err, &authErr) || authErr.Reason != hmacauth.ReasonMalformedNonce {
			t.Fatalf("nonce %q gave %v", bad, err)
		}
	}
}

func TestVerifyRejectsASwappedNonce(t *testing.T) {
	// Swapping the nonce invalidates the MAC, which is what makes a nonce
	// store meaningful later: the signature is bound to this nonce.
	v := newVerifier()
	h := signedHeader(t, key, fixedNow(), method, path, body)
	h.Set(hmacauth.HeaderNonce, "fedcba9876543210fedcba9876543210")
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonBadSignature)
}

func TestNewNonceIsRandomAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		n, err := hmacauth.NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if len(n) != hmacauth.MinNonceHexLen {
			t.Fatalf("NewNonce() = %q, want %d hex characters", n, hmacauth.MinNonceHexLen)
		}
		if n != strings.ToLower(n) {
			t.Fatalf("NewNonce() = %q, want lowercase hex", n)
		}
		if seen[n] {
			t.Fatalf("NewNonce() repeated %q", n)
		}
		seen[n] = true
	}
}

func TestSignRequestSetsAllThreeHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://search:8081"+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := hmacauth.SignRequest(key, req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	for _, h := range []string{hmacauth.HeaderTimestamp, hmacauth.HeaderNonce, hmacauth.HeaderSignature} {
		if req.Header.Get(h) == "" {
			t.Fatalf("SignRequest left %s empty", h)
		}
	}
	v := &hmacauth.Verifier{Key: key, MaxSkew: 300 * time.Second}
	if err := v.Verify(req.Method, req.URL.Path, req.Header, body); err != nil {
		t.Fatalf("a request signed by SignRequest failed verification: %v", err)
	}
}

// TestVerifyRejectsASignatureThatDiffersOnlyInTheLastByte exists because a
// comparison that stops early — a prefix compare, or a hand-rolled loop with a
// `break` — passes every test that uses an unrelated wrong key, since two
// unrelated MACs almost always differ in the first byte. This forges a MAC that
// shares all but the final byte with the correct one, so only a full-length
// comparison rejects it.
func TestVerifyRejectsASignatureThatDiffersOnlyInTheLastByte(t *testing.T) {
	v := newVerifier()
	_, correct := hmacauth.SignAt(key, method, path, fixedNow(), testNonce, body)

	mac := strings.TrimPrefix(correct, "v1=")
	raw, err := hex.DecodeString(mac)
	if err != nil {
		t.Fatalf("decoding the correct MAC: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	forged := "v1=" + hex.EncodeToString(raw)
	if forged == correct {
		t.Fatal("fixture error: the forgery equals the correct signature")
	}

	h := signedHeader(t, key, fixedNow(), method, path, body)
	h.Set(hmacauth.HeaderSignature, forged)
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonBadSignature)
}

// The mirror case: a MAC that differs only in the FIRST byte and is otherwise
// correct must also be rejected. Together the two pin the comparison to the
// whole value rather than to either end of it.
func TestVerifyRejectsASignatureThatDiffersOnlyInTheFirstByte(t *testing.T) {
	v := newVerifier()
	_, correct := hmacauth.SignAt(key, method, path, fixedNow(), testNonce, body)

	raw, err := hex.DecodeString(strings.TrimPrefix(correct, "v1="))
	if err != nil {
		t.Fatalf("decoding the correct MAC: %v", err)
	}
	raw[0] ^= 0x01

	h := signedHeader(t, key, fixedNow(), method, path, body)
	h.Set(hmacauth.HeaderSignature, "v1="+hex.EncodeToString(raw))
	wantReason(t, v.Verify(method, path, h, body), hmacauth.ReasonBadSignature)
}

// TestVerifyUsesTheDocumentedConstantTimePrimitive is a source-level guard.
// Constant-time behaviour cannot be proved by a functional test, so what is
// asserted here is the thing that can be: that the comparison goes through
// crypto/hmac.Equal, the documented constant-time primitive, rather than == or
// bytes.Equal. The two tests above cover the functional half.
func TestVerifyUsesTheDocumentedConstantTimePrimitive(t *testing.T) {
	source, err := os.ReadFile("hmacauth.go")
	if err != nil {
		t.Fatalf("reading the package source: %v", err)
	}
	if !strings.Contains(string(source), "hmac.Equal(provided, expected)") {
		t.Fatal("the MAC comparison no longer goes through hmac.Equal; a non-constant-time comparison leaks how much of a forgery was correct")
	}
	for _, forbidden := range []string{"bytes.Equal(provided", "provided == ", "string(provided) =="} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("the source contains a non-constant-time comparison: %s", forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// The timestamp window, across the whole magnitude range, in both directions.
//
// This table is the regression for the BLOCKER found at 7f483ad: the window was
// computed as now.Sub(time.Unix(ts,0)) with the sign folded, time.Time.Sub
// saturates at math.MinInt64 for a far-future argument, and negating
// math.MinInt64 yields itself — so the comparison failed open and a validly
// signed request with ts=253402300799 was accepted and never expired. Every row
// below carries a GENUINE signature over its own fields, so only the range or
// window rule can refuse it.
// ---------------------------------------------------------------------------

const windowNow int64 = 1789929649 // 2026-09-20, inside the contract's range

func verifyAtWindowNow(t *testing.T, ts string) error {
	t.Helper()
	const p = "/internal/v1/search"
	body := []byte(`{}`)
	h := http.Header{}
	h.Set(hmacauth.HeaderTimestamp, ts)
	h.Set(hmacauth.HeaderNonce, testNonce)
	h.Set(hmacauth.HeaderSignature, hmacauth.Sign(key, http.MethodPost, p, ts, testNonce, body))
	v := &hmacauth.Verifier{
		Key:     key,
		MaxSkew: 300 * time.Second,
		Now:     func() time.Time { return time.Unix(windowNow, 0).UTC() },
	}
	return v.Verify(http.MethodPost, p, h, body)
}

func TestTimestampWindowClosesAcrossTheWholeMagnitudeRange(t *testing.T) {
	cases := []struct {
		name   string
		ts     string
		accept bool
		reason hmacauth.Reason
	}{
		// Inside the window.
		{"now", "1789929649", true, ""},
		{"299 s in the past", "1789929350", true, ""},
		{"299 s in the future", "1789929948", true, ""},
		{"exactly 300 s in the past", "1789929349", true, ""},
		{"exactly 300 s in the future", "1789929949", true, ""},

		// Just outside the window, both directions.
		{"301 s in the past", "1789929348", false, hmacauth.ReasonStaleTimestamp},
		{"301 s in the future", "1789929950", false, hmacauth.ReasonStaleTimestamp},

		// Inside the absolute range but far outside the window.
		{"the range floor", "1000000000", false, hmacauth.ReasonStaleTimestamp},
		{"the range ceiling", "4102444800", false, hmacauth.ReasonStaleTimestamp},
		{"one below the ceiling", "4102444799", false, hmacauth.ReasonStaleTimestamp},

		// Outside the absolute range — the rows that were ACCEPTED at 7f483ad.
		{"one below the range floor", "999999999", false, hmacauth.ReasonTimestampRange},
		{"one above the range ceiling", "4102444801", false, hmacauth.ReasonTimestampRange},
		{"the verifier's reported boundary", "11013301709", false, hmacauth.ReasonTimestampRange},
		{"one below that boundary", "11013301708", false, hmacauth.ReasonTimestampRange},
		{"year 9999", "253402300799", false, hmacauth.ReasonTimestampRange},
		{"1<<62", "4611686018427387904", false, hmacauth.ReasonTimestampRange},
		{"max int64", "9223372036854775807", false, hmacauth.ReasonTimestampRange},
		{"max int64 plus one, so ParseInt overflows", "9223372036854775808", false, hmacauth.ReasonTimestampRange},
		{"twenty nines", "99999999999999999999", false, hmacauth.ReasonTimestampRange},

		// Shape rules: refused, never normalised.
		{"zero", "0", false, hmacauth.ReasonMalformedTimestamp},
		{"one", "1", false, hmacauth.ReasonTimestampRange},
		{"leading zero", "01789929649", false, hmacauth.ReasonMalformedTimestamp},
		{"leading zeros", "0001789929649", false, hmacauth.ReasonMalformedTimestamp},
		{"leading plus", "+1789929649", false, hmacauth.ReasonMalformedTimestamp},
		{"leading minus", "-1789929649", false, hmacauth.ReasonMalformedTimestamp},
		{"leading space", " 1789929649", false, hmacauth.ReasonMalformedTimestamp},
		{"trailing space", "1789929649 ", false, hmacauth.ReasonMalformedTimestamp},
		{"surrounding space", "  1789929649  ", false, hmacauth.ReasonMalformedTimestamp},
		{"underscores", "1_789_929_649", false, hmacauth.ReasonMalformedTimestamp},
		{"hex", "0x6AA2F5B1", false, hmacauth.ReasonMalformedTimestamp},
		{"fractional", "1789929649.0", false, hmacauth.ReasonMalformedTimestamp},
		{"exponent", "1.78e9", false, hmacauth.ReasonMalformedTimestamp},
		// An empty header VALUE is present-but-malformed; a wholly absent
		// header is ReasonMissingTimestamp and is covered by
		// TestVerifyRejectsAMissingTimestamp.
		{"empty value", "", false, hmacauth.ReasonMalformedTimestamp},
		{"letters", "yesterday", false, hmacauth.ReasonMalformedTimestamp},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyAtWindowNow(t, tc.ts)
			if tc.accept {
				if err != nil {
					t.Fatalf("ts=%q was refused: %v", tc.ts, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ts=%q was ACCEPTED; the window must close at every magnitude, in both directions", tc.ts)
			}
			var authErr *hmacauth.Error
			if !errors.As(err, &authErr) {
				t.Fatalf("ts=%q gave %v, not *hmacauth.Error", tc.ts, err)
			}
			if tc.reason != "" && authErr.Reason != tc.reason {
				t.Fatalf("ts=%q reason = %q, want %q", tc.ts, authErr.Reason, tc.reason)
			}
		})
	}
}

// The arithmetic must be on plain int64 seconds. This pins the property the
// BLOCKER violated: no value derived from an unvalidated header ever becomes a
// time.Duration, so saturation is unreachable rather than merely unlikely.
func TestTheSkewArithmeticCannotSaturate(t *testing.T) {
	source, err := os.ReadFile("hmacauth.go")
	if err != nil {
		t.Fatalf("reading the package source: %v", err)
	}
	src := string(source)
	if !strings.Contains(src, "skewSeconds := nowUnix - unixSeconds") {
		t.Error("the skew is no longer computed on plain int64 seconds; deriving it from a time value re-opens the saturating-subtraction hole")
	}
	for _, forbidden := range []string{
		"v.now().Sub(",
		"Sub(time.Unix(unixSeconds",
		"time.Since(time.Unix(unixSeconds",
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("the source computes the window through %q; time.Time.Sub saturates at math.MinInt64 and negating that yields itself, so the check fails open", forbidden)
		}
	}
	// And the range check must precede the arithmetic.
	rangeIdx := strings.Index(src, "unixSeconds < MinTimestampUnix")
	skewIdx := strings.Index(src, "skewSeconds := nowUnix - unixSeconds")
	if rangeIdx < 0 || skewIdx < 0 {
		t.Fatal("could not locate the range check and the skew computation")
	}
	if rangeIdx > skewIdx {
		t.Error("the absolute-range check must run BEFORE any arithmetic on the timestamp")
	}
}

// A verifier whose OWN clock is outside the absolute range fails closed, as the
// contract requires: "A verifier whose own clock falls outside the absolute
// range MUST fail closed."
func TestAVerifierWithAnInsaneClockFailsClosed(t *testing.T) {
	const p = "/internal/v1/search"
	b := []byte(`{}`)
	for _, nowUnix := range []int64{0, 1, 999999999, 4102444801, 253402300799, 1 << 62} {
		ts := strconv.FormatInt(nowUnix, 10)
		h := http.Header{}
		h.Set(hmacauth.HeaderTimestamp, ts)
		h.Set(hmacauth.HeaderNonce, testNonce)
		h.Set(hmacauth.HeaderSignature, hmacauth.Sign(key, http.MethodPost, p, ts, testNonce, b))
		v := &hmacauth.Verifier{
			Key:     key,
			MaxSkew: 300 * time.Second,
			Now:     func() time.Time { return time.Unix(nowUnix, 0).UTC() },
		}
		err := v.Verify(http.MethodPost, p, h, b)
		if err == nil {
			t.Fatalf("a verifier whose clock reads %d accepted a request; it must fail closed", nowUnix)
		}
		var authErr *hmacauth.Error
		if !errors.As(err, &authErr) || authErr.Reason != hmacauth.ReasonVerifierClock {
			t.Fatalf("clock %d gave %v, want %q", nowUnix, err, hmacauth.ReasonVerifierClock)
		}
	}
}

// Verbatim fields: a method or nonce that is not already canonical is refused,
// not rewritten.
func TestNonCanonicalFieldsAreRefusedNotRewritten(t *testing.T) {
	const p = "/internal/v1/search"
	b := []byte(`{}`)
	ts := strconv.FormatInt(windowNow, 10)

	check := func(t *testing.T, method, nonce string, want hmacauth.Reason) {
		t.Helper()
		h := http.Header{}
		h.Set(hmacauth.HeaderTimestamp, ts)
		h.Set(hmacauth.HeaderNonce, nonce)
		h.Set(hmacauth.HeaderSignature, hmacauth.Sign(key, method, p, ts, nonce, b))
		v := &hmacauth.Verifier{Key: key, MaxSkew: 300 * time.Second, Now: func() time.Time { return time.Unix(windowNow, 0).UTC() }}
		err := v.Verify(method, p, h, b)
		if err == nil {
			t.Fatalf("method=%q nonce=%q was ACCEPTED; the contract refuses non-canonical fields rather than normalising them", method, nonce)
		}
		var authErr *hmacauth.Error
		if !errors.As(err, &authErr) || authErr.Reason != want {
			t.Fatalf("method=%q nonce=%q gave %v, want %q", method, nonce, err, want)
		}
	}

	t.Run("lowercase method", func(t *testing.T) { check(t, "post", testNonce, hmacauth.ReasonMalformedMethod) })
	t.Run("mixed-case method", func(t *testing.T) { check(t, "Post", testNonce, hmacauth.ReasonMalformedMethod) })
	t.Run("uppercase hex nonce", func(t *testing.T) {
		check(t, http.MethodPost, strings.ToUpper(testNonce), hmacauth.ReasonMalformedNonce)
	})
	t.Run("nonce above the 128 ceiling", func(t *testing.T) {
		check(t, http.MethodPost, strings.Repeat("a", 130), hmacauth.ReasonMalformedNonce)
	})
	t.Run("nonce exactly at the 128 ceiling is fine", func(t *testing.T) {
		nonce := strings.Repeat("ab", 64)
		if len(nonce) != hmacauth.MaxNonceHexLen {
			t.Fatalf("fixture is %d chars", len(nonce))
		}
		h := http.Header{}
		h.Set(hmacauth.HeaderTimestamp, ts)
		h.Set(hmacauth.HeaderNonce, nonce)
		h.Set(hmacauth.HeaderSignature, hmacauth.Sign(key, http.MethodPost, p, ts, nonce, b))
		v := &hmacauth.Verifier{Key: key, MaxSkew: 300 * time.Second, Now: func() time.Time { return time.Unix(windowNow, 0).UTC() }}
		if err := v.Verify(http.MethodPost, p, h, b); err != nil {
			t.Fatalf("a 128-character nonce was refused: %v", err)
		}
	})
}

// Each of the three headers must appear exactly once; a duplicate is refused
// rather than resolved to the first or the last value.
func TestDuplicatedHeadersAreRefused(t *testing.T) {
	const p = "/internal/v1/search"
	b := []byte(`{}`)
	ts := strconv.FormatInt(windowNow, 10)
	sig := hmacauth.Sign(key, http.MethodPost, p, ts, testNonce, b)

	for _, name := range []string{hmacauth.HeaderTimestamp, hmacauth.HeaderNonce, hmacauth.HeaderSignature} {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			h.Set(hmacauth.HeaderTimestamp, ts)
			h.Set(hmacauth.HeaderNonce, testNonce)
			h.Set(hmacauth.HeaderSignature, sig)
			// A second, identical value: even agreeing duplicates are refused,
			// because the ambiguity is structural.
			h.Add(name, h.Get(name))

			v := &hmacauth.Verifier{Key: key, MaxSkew: 300 * time.Second, Now: func() time.Time { return time.Unix(windowNow, 0).UTC() }}
			err := v.Verify(http.MethodPost, p, h, b)
			if err == nil {
				t.Fatalf("a duplicated %s was accepted", name)
			}
			var authErr *hmacauth.Error
			if !errors.As(err, &authErr) || authErr.Reason != hmacauth.ReasonDuplicateHeader {
				t.Fatalf("duplicated %s gave %v, want %q", name, err, hmacauth.ReasonDuplicateHeader)
			}
		})
	}
}

// An uppercase-hex MAC is refused: hex.DecodeString would accept it, and the
// contract requires lowercase.
func TestAnUppercaseHexSignatureIsRefused(t *testing.T) {
	const p = "/internal/v1/search"
	b := []byte(`{}`)
	ts := strconv.FormatInt(windowNow, 10)
	sig := hmacauth.Sign(key, http.MethodPost, p, ts, testNonce, b)

	h := http.Header{}
	h.Set(hmacauth.HeaderTimestamp, ts)
	h.Set(hmacauth.HeaderNonce, testNonce)
	h.Set(hmacauth.HeaderSignature, "v1="+strings.ToUpper(strings.TrimPrefix(sig, "v1=")))

	v := &hmacauth.Verifier{Key: key, MaxSkew: 300 * time.Second, Now: func() time.Time { return time.Unix(windowNow, 0).UTC() }}
	err := v.Verify(http.MethodPost, p, h, b)
	if err == nil {
		t.Fatal("an uppercase-hex signature was accepted")
	}
	var authErr *hmacauth.Error
	if !errors.As(err, &authErr) || authErr.Reason != hmacauth.ReasonMalformedSignature {
		t.Fatalf("gave %v, want %q", err, hmacauth.ReasonMalformedSignature)
	}
}
