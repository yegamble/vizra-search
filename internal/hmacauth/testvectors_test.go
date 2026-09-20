package hmacauth_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/hmacauth"
)

// The normative conformance vectors, vendored byte-identically from vizra-core.
// The file's own header: "Owned by vizra-core; vizra-search vendors a
// byte-identical copy and tests against it. If the two repositories disagree
// here they would sign different bytes and every internal call would 401 in
// production."
const vectorsPath = "../../api/search-hmac-testvectors.json"

type vector struct {
	Name           string            `json:"name"`
	RejectBecause  string            `json:"reject_because"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Timestamp      string            `json:"timestamp"`
	Nonce          string            `json:"nonce"`
	BodyUTF8       string            `json:"body_utf8"`
	BodySHA256Hex  string            `json:"body_sha256_hex"`
	CanonicalStr   string            `json:"canonical_string"`
	Signature      string            `json:"signature"`
	MustReject     bool              `json:"must_reject"`
	ExtraHeaders   map[string]string `json:"extra_headers"`
	OmittedHeaders []string          `json:"omitted_headers"`
}

type vectorWindow struct {
	MaxClockSkewSeconds int64 `json:"max_clock_skew_seconds"`
	MinTimestampUnix    int64 `json:"min_timestamp_unix"`
	MaxTimestampUnix    int64 `json:"max_timestamp_unix"`
}

type vectorFile struct {
	Scheme              string       `json:"scheme"`
	KeyUTF8             string       `json:"key_utf8"`
	MaxClockSkewSeconds int64        `json:"max_clock_skew_seconds"`
	VerifierNowUnix     int64        `json:"verifier_now_unix"`
	Window              vectorWindow `json:"window"`
	Vectors             []vector     `json:"vectors"`
	NegativeVectors     []vector     `json:"negative_vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("reading the vendored conformance vectors: %v", err)
	}
	var vf vectorFile
	dec := json.NewDecoder(newReader(raw))
	if err := dec.Decode(&vf); err != nil {
		t.Fatalf("%s is not JSON: %v", vectorsPath, err)
	}
	if vf.Scheme != hmacauth.SignatureVersion {
		t.Fatalf("the vectors declare scheme %q, this package implements %q", vf.Scheme, hmacauth.SignatureVersion)
	}
	// A vector file that has been emptied out is not a conformance check.
	if len(vf.Vectors) == 0 {
		t.Fatal("the vendored vector file declares no ACCEPT vectors")
	}
	if len(vf.NegativeVectors) == 0 {
		t.Fatal("the vendored vector file declares no REJECT vectors; agreeing on the accept set while disagreeing on the reject set is exactly how the two implementations diverged")
	}
	return vf
}

// verifierAt builds a verifier pinned to a given clock and to the vector
// file's declared window, so the vectors judge this implementation and never
// the wall clock.
func verifierAt(vf vectorFile, nowUnix int64) *hmacauth.Verifier {
	return &hmacauth.Verifier{
		Key:     []byte(vf.KeyUTF8),
		MaxSkew: time.Duration(vf.MaxClockSkewSeconds) * time.Second,
		Now:     func() time.Time { return time.Unix(nowUnix, 0).UTC() },
	}
}

// verifierFor is the clock the file declares for the REJECT half. The file's
// own header scopes it: "Negative vectors are judged against `verifier_now_unix`
// as the verifier's clock." The ACCEPT vectors carry timestamps of their own
// (1789000000 … 1789000789, spread wider than the 300 s window), so each is
// judged against a clock at its own timestamp; judging them all against
// verifier_now_unix would refuse two of them for skew and prove nothing about
// the canonicalisation they exist to pin.
func verifierFor(vf vectorFile) *hmacauth.Verifier {
	return verifierAt(vf, vf.VerifierNowUnix)
}

func headersFor(v vector) http.Header {
	h := http.Header{}
	omitted := map[string]bool{}
	for _, name := range v.OmittedHeaders {
		omitted[http.CanonicalHeaderKey(name)] = true
	}
	set := func(name, value string) {
		if !omitted[http.CanonicalHeaderKey(name)] {
			h.Set(name, value)
		}
	}
	set(hmacauth.HeaderTimestamp, v.Timestamp)
	set(hmacauth.HeaderNonce, v.Nonce)
	set(hmacauth.HeaderSignature, v.Signature)
	// extra_headers carries a SECOND value for an existing header, which is how
	// the duplicate-header vector is expressed.
	for name, value := range v.ExtraHeaders {
		h.Add(name, value)
	}
	return h
}

// TestTheVendoredVectorsCoverTheContractsWindow guards the vectors themselves:
// this implementation's absolute bounds must be the ones the contract declares.
func TestTheVendoredVectorsCoverTheContractsWindow(t *testing.T) {
	vf := loadVectors(t)
	if vf.Window.MinTimestampUnix != hmacauth.MinTimestampUnix {
		t.Errorf("min_timestamp_unix = %d, this package uses %d", vf.Window.MinTimestampUnix, hmacauth.MinTimestampUnix)
	}
	if vf.Window.MaxTimestampUnix != hmacauth.MaxTimestampUnix {
		t.Errorf("max_timestamp_unix = %d, this package uses %d", vf.Window.MaxTimestampUnix, hmacauth.MaxTimestampUnix)
	}
	if vf.Window.MaxClockSkewSeconds != 300 {
		t.Errorf("max_clock_skew_seconds = %d, the contract fixes 300", vf.Window.MaxClockSkewSeconds)
	}
}

// TestVerifierReproducesTheSharedVectors is the ACCEPT half. For each vector
// the canonical string and the signature must reproduce byte for byte — which
// is the property that makes the two repositories sign the same bytes — and
// Verify must accept the request.
func TestVerifierReproducesTheSharedVectors(t *testing.T) {
	vf := loadVectors(t)

	for _, vec := range vf.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			body := []byte(vec.BodyUTF8)

			// The body digest the vector declares.
			sum := sha256Hex(body)
			if sum != vec.BodySHA256Hex {
				t.Fatalf("body sha256 = %s, vector says %s", sum, vec.BodySHA256Hex)
			}

			// The canonical string, byte for byte.
			got := hmacauth.SigningString(vec.Method, vec.Path, vec.Timestamp, vec.Nonce, body)
			if got != vec.CanonicalStr {
				t.Fatalf("canonical string differs from the shared vector.\n got: %q\nwant: %q", got, vec.CanonicalStr)
			}

			// The signature, byte for byte.
			sig := hmacauth.Sign([]byte(vf.KeyUTF8), vec.Method, vec.Path, vec.Timestamp, vec.Nonce, body)
			if sig != vec.Signature {
				t.Fatalf("signature differs from the shared vector.\n got: %s\nwant: %s", sig, vec.Signature)
			}

			// And a verifier whose clock sits at the vector's own timestamp
			// accepts it.
			ts, err := strconv.ParseInt(vec.Timestamp, 10, 64)
			if err != nil {
				t.Fatalf("ACCEPT vector %q has a non-numeric timestamp %q", vec.Name, vec.Timestamp)
			}
			v := verifierAt(vf, ts)
			if err := v.Verify(vec.Method, vec.Path, headersFor(vec), body); err != nil {
				t.Fatalf("Verify refused an ACCEPT vector: %v", err)
			}
		})
	}
}

// TestVerifierRefusesEveryNegativeVector is the REJECT half, and the contract
// says it matters more: "agreeing on what is accepted while disagreeing on what
// is rejected is how two implementations of the same scheme diverge." Every
// negative vector carries a genuine signature over exactly the fields as sent,
// so only the stated rule can refuse it.
func TestVerifierRefusesEveryNegativeVector(t *testing.T) {
	vf := loadVectors(t)
	v := verifierFor(vf)

	for _, vec := range vf.NegativeVectors {
		t.Run(vec.Name, func(t *testing.T) {
			if !vec.MustReject {
				t.Fatalf("negative vector %q does not carry must_reject", vec.Name)
			}
			body := []byte(vec.BodyUTF8)

			// The vector's signature is genuine over its own canonical string,
			// so a rejection cannot be blamed on a wrong MAC.
			if vec.CanonicalStr != "" {
				sig := hmacauth.Sign([]byte(vf.KeyUTF8), vec.Method, vec.Path, vec.Timestamp, vec.Nonce, body)
				if sig != vec.Signature {
					t.Fatalf("this negative vector's signature is not the one this implementation computes over its stated fields, so the vector cannot isolate the rule it names (%s).\n got: %s\nwant: %s",
						vec.RejectBecause, sig, vec.Signature)
				}
			}

			err := v.Verify(vec.Method, vec.Path, headersFor(vec), body)
			if err == nil {
				t.Fatalf("Verify ACCEPTED a vector the contract says must be rejected.\n  rule: %s", vec.RejectBecause)
			}
			// The uniform-401 rule: every rejection is the same typed error.
			var authErr *hmacauth.Error
			if !errors.As(err, &authErr) {
				t.Fatalf("rejection is not *hmacauth.Error: %v", err)
			}
			if !errors.Is(err, hmacauth.ErrUnauthorized) {
				t.Fatalf("rejection does not match ErrUnauthorized: %v", err)
			}
		})
	}
}

// TestEveryNamedRejectClassIsCovered guards against the vector file being
// trimmed: the classes that caused the real divergence must stay present.
func TestEveryNamedRejectClassIsCovered(t *testing.T) {
	vf := loadVectors(t)
	present := map[string]bool{}
	for _, vec := range vf.NegativeVectors {
		present[vec.Name] = true
	}
	for _, required := range []string{
		"method-lowercase",
		"timestamp-leading-plus",
		"timestamp-leading-zero",
		"timestamp-leading-space",
		"timestamp-trailing-space",
		"timestamp-future-past-window",
		"timestamp-stale-past-window",
		"timestamp-year-10000",
		"timestamp-max-int64",
		"nonce-uppercase-hex",
		"nonce-too-short",
		"timestamp-duplicated-header",
	} {
		if !present[required] {
			t.Errorf("the vendored vectors no longer carry the %q reject case", required)
		}
	}
}

func sha256Hex(b []byte) string {
	sum := sha256Sum(b)
	return hex.EncodeToString(sum[:])
}
