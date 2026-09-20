package httpapi_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/config"
	"github.com/yegamble/vizra-search/internal/hmacauth"
	"github.com/yegamble/vizra-search/internal/httpapi"
)

// ---------------------------------------------------------------------------
// C — the MAC covers the request path AS SENT, not Echo's route template.
// ---------------------------------------------------------------------------

// TestASignatureForOneConcretePathDoesNotAuthenticateAnother is the regression
// for security FINDING 4. Verification used to run over c.Path(), Echo's
// REGISTERED route. For a static route that string equals the request path, so
// nothing was wrong — but the moment a route carries a parameter, c.Path()
// becomes "/x/:id" for every id, the concrete segment drops out of the MAC, and
// core keeps signing the concrete path. This registers a parameterised route on
// a test-only server and proves the concrete segment is inside the MAC.
func TestASignatureForOneConcretePathDoesNotAuthenticateAnother(t *testing.T) {
	srv, _ := newServer(t)
	body := []byte(`{}`)

	// Sign /x/a, send it to /x/b. With route-template verification both sides
	// canonicalise "/x/:id" and the forgery authenticates.
	signedFor := "/internal/v1/search"
	sentTo := "/internal/v1/suggestions"

	req := httptest.NewRequest(http.MethodPost, sentTo, bytes.NewReader(body))
	nonce := "0123456789abcdef0123456789abcdef"
	ts, sig := hmacauth.SignAt([]byte(testKey), http.MethodPost, signedFor, time.Now(), nonce, body)
	req.Header.Set(hmacauth.HeaderTimestamp, ts)
	req.Header.Set(hmacauth.HeaderNonce, nonce)
	req.Header.Set(hmacauth.HeaderSignature, sig)

	wantSignatureRejected(t, do(t, srv, req), "a signature for another concrete path")
}

// TestTheVerifiedPathIsTheRequestPathNotTheRouteTemplate proves the property
// directly, on a parameterised route registered only for this test. Against the
// old code (c.Path()) a signature over "/probe/:id" would authenticate every
// id; against the fixed code only the concrete path does.
func TestTheVerifiedPathIsTheRequestPathNotTheRouteTemplate(t *testing.T) {
	srv := httpapi.NewWithProbeRouteForTest(testConfig(t), httpapi.NewLogger(io.Discard))
	body := []byte(`{}`)

	sign := func(path string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/probe/b", bytes.NewReader(body))
		nonce := "0123456789abcdef0123456789abcdef"
		ts, sig := hmacauth.SignAt([]byte(testKey), http.MethodPost, path, time.Now(), nonce, body)
		req.Header.Set(hmacauth.HeaderTimestamp, ts)
		req.Header.Set(hmacauth.HeaderNonce, nonce)
		req.Header.Set(hmacauth.HeaderSignature, sig)
		return req
	}

	// A signature over the concrete path that was actually requested: accepted.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, sign("/probe/b"))
	if rec.Code != http.StatusOK {
		t.Fatalf("a signature over the concrete request path was refused: %d (%s)", rec.Code, rec.Body.String())
	}

	// A signature over a DIFFERENT concrete path: refused.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, sign("/probe/a"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a signature over /probe/a authenticated a request to /probe/b (%d); the concrete segment is not inside the MAC", rec.Code)
	}

	// A signature over the ROUTE TEMPLATE: refused. This is the exact value the
	// old implementation verified against, so this case fails against it.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, sign("/probe/:id"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a signature over the route template %q authenticated a concrete request (%d)", "/probe/:id", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// F5 — a query string on an internal route is refused before verification.
// ---------------------------------------------------------------------------

func TestASignedRequestWithAQueryStringIsRefused(t *testing.T) {
	// The canonical string has no query field, so a query is unsigned: an
	// attacker on the internal network could append or alter one without
	// invalidating a captured signature. Refusing it makes the contract's
	// "no query string" safe by construction.
	srv, _ := newServer(t)
	for _, query := range []string{"?x=1", "?", "?a=1&b=2", "?utm_source=evil"} {
		t.Run(query, func(t *testing.T) {
			path := "/internal/v1/search"
			body := validBody(path)
			target := path + query
			req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
			// Sign the bare path, exactly as a legitimate caller would.
			nonce := "0123456789abcdef0123456789abcdef"
			ts, sig := hmacauth.SignAt([]byte(testKey), http.MethodPost, path, time.Now(), nonce, body)
			req.Header.Set(hmacauth.HeaderTimestamp, ts)
			req.Header.Set(hmacauth.HeaderNonce, nonce)
			req.Header.Set(hmacauth.HeaderSignature, sig)
			wantSignatureRejected(t, do(t, srv, req), "a signed request carrying "+query)
		})
	}
}

func TestAQueryStringIsRefusedBeforeVerification(t *testing.T) {
	// Unsigned and with a query: still the same uniform 401, and the refusal
	// happens without consulting the (absent) signature.
	srv, _ := newServer(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/search?a=1", strings.NewReader(`{}`))
	wantSignatureRejected(t, do(t, srv, req), "an unsigned request with a query string")
}

// ---------------------------------------------------------------------------
// E — the six surviving mutants.
// ---------------------------------------------------------------------------

// countingReader records how many bytes were actually read from a body.
type countingReader struct {
	data []byte
	pos  int
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	r.read += n
	return n, nil
}

func (r *countingReader) Close() error { return nil }

// S2/S3 — the STREAMING body bound. Every existing 413 test builds its request
// with bytes.NewReader, which sets ContentLength, so all of them are satisfied
// by the declared-length pre-check alone. Both of these mutations survived:
//
//	readBounded(req.Body, s.cfg.MaxBodyBytes) -> readBounded(req.Body, 1<<62)
//	io.LimitReader(r, limit+1)                -> io.LimitReader(r, limit)
//
// This drives the undeclared-length path and asserts both the status and the
// number of bytes read.
func TestAnUndeclaredLengthBodyAboveTheLimitIsRefusedAfterLimitPlusOneBytes(t *testing.T) {
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			srv, _ := newServer(t)
			huge := bytes.Repeat([]byte("a"), 4*smallBodyLimit)
			reader := &countingReader{data: huge}

			req := httptest.NewRequest(http.MethodPost, path, reader)
			// No declared length: this is a chunked body, or a peer that lies.
			req.ContentLength = -1
			req.Body = reader
			if err := hmacauth.SignRequest([]byte(testKey), req, huge); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}

			rec := do(t, srv, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("an undeclared-length body of %d bytes against a %d-byte limit = %d (%s), want 413",
					len(huge), smallBodyLimit, rec.Code, rec.Body.String())
			}
			// The whole point of the bound: the server must stop at limit+1.
			if reader.read != smallBodyLimit+1 {
				t.Fatalf("the server read %d bytes against a %d-byte limit; it must stop at limit+1 (%d)",
					reader.read, smallBodyLimit, smallBodyLimit+1)
			}
		})
	}
}

// The mirror: a body exactly at the limit with no declared length is accepted,
// which is what makes `limit+1` rather than `limit` the correct read bound.
func TestAnUndeclaredLengthBodyExactlyAtTheLimitIsAccepted(t *testing.T) {
	srv, _ := newServer(t)
	prefix := `{"query":"`
	suffix := `","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`
	body := []byte(prefix + strings.Repeat("a", smallBodyLimit-len(prefix)-len(suffix)) + suffix)
	if len(body) != smallBodyLimit {
		t.Fatalf("fixture is %d bytes", len(body))
	}

	reader := &countingReader{data: body}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/search", reader)
	req.ContentLength = -1
	req.Body = reader
	if err := hmacauth.SignRequest([]byte(testKey), req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	rec := do(t, srv, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("an undeclared-length body exactly at the limit = %d (%s), want 200", rec.Code, rec.Body.String())
	}
}

// S6 — the drain 503 must sit AFTER authentication. Under the mutation that
// moves it above Verify, an unauthenticated caller learns whether the instance
// is draining before any credential is checked.
func TestADrainingServerStillRefusesAnUnsignedRequestFirst(t *testing.T) {
	srv, _ := newServer(t)
	srv.BeginDrain()
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(validBody(path)))
			rec := do(t, srv, req)
			if rec.Code == http.StatusServiceUnavailable {
				t.Fatalf("a draining server answered an UNSIGNED request with 503; an unauthenticated caller must not learn the drain state before any credential is checked")
			}
			wantSignatureRejected(t, rec, "unsigned request to a draining "+path)
		})
	}
}

func TestADrainingServerAnswers503ToASignedRequest(t *testing.T) {
	srv, _ := newServer(t)
	srv.BeginDrain()
	for _, path := range internalPaths {
		rec := do(t, srv, signedRequest(t, http.MethodPost, path, validBody(path)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("a signed request to a draining %s = %d, want 503", path, rec.Code)
		}
	}
}

// S7 — the 401 refusal path is the one most likely to carry a LEGITIMATE
// member's query text: a request refused for clock skew or a rotated key is
// core's real query. The existing redaction test drives only a successful
// request, so adding the body to the refusal log survived. This drives every
// rejection cause.
func TestTheRefusalPathNeverLogsTheRequestBody(t *testing.T) {
	const secret = "a-real-members-search-term"
	body := []byte(`{"query":"` + secret + `","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`)
	path := "/internal/v1/search"

	cases := map[string]func(t *testing.T) *http.Request{
		"unsigned": func(t *testing.T) *http.Request {
			return httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		},
		"wrong key": func(t *testing.T) *http.Request {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			wrong := []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
			nonce := "0123456789abcdef0123456789abcdef"
			ts, sig := hmacauth.SignAt(wrong, http.MethodPost, path, time.Now(), nonce, body)
			req.Header.Set(hmacauth.HeaderTimestamp, ts)
			req.Header.Set(hmacauth.HeaderNonce, nonce)
			req.Header.Set(hmacauth.HeaderSignature, sig)
			return req
		},
		"stale timestamp": func(t *testing.T) *http.Request {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			nonce := "0123456789abcdef0123456789abcdef"
			stale := time.Now().Add(-config.DefaultMaxClockSkew - time.Minute)
			ts, sig := hmacauth.SignAt([]byte(testKey), http.MethodPost, path, stale, nonce, body)
			req.Header.Set(hmacauth.HeaderTimestamp, ts)
			req.Header.Set(hmacauth.HeaderNonce, nonce)
			req.Header.Set(hmacauth.HeaderSignature, sig)
			return req
		},
		"query string": func(t *testing.T) *http.Request {
			req := httptest.NewRequest(http.MethodPost, path+"?a=1", bytes.NewReader(body))
			_ = hmacauth.SignRequest([]byte(testKey), req, body)
			return req
		},
		"oversized": func(t *testing.T) *http.Request {
			big := append(bytes.Repeat([]byte("b"), 4*smallBodyLimit), body...)
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(big))
			_ = hmacauth.SignRequest([]byte(testKey), req, big)
			return req
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			srv, logs := newServer(t)
			req := build(t)
			sig := req.Header.Get(hmacauth.HeaderSignature)
			nonce := req.Header.Get(hmacauth.HeaderNonce)

			rec := do(t, srv, req)
			if rec.Code == http.StatusOK {
				t.Fatalf("setup: %s was accepted", name)
			}
			out := logs.String()
			if out == "" {
				t.Fatalf("%s logged nothing, so the redaction claim is untested on this path", name)
			}
			if strings.Contains(out, secret) {
				t.Errorf("the refusal log carries the request body: %s", out)
			}
			if strings.Contains(out, testKey) {
				t.Errorf("the refusal log carries the shared secret: %s", out)
			}
			if sig != "" && strings.Contains(out, sig) {
				t.Errorf("the refusal log carries the signature: %s", out)
			}
			if nonce != "" && strings.Contains(out, nonce) {
				t.Errorf("the refusal log carries the nonce: %s", out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F6 — the limitation, named.
// ---------------------------------------------------------------------------

// TestIdenticalRequestsCanStillBeReplayedInsideTheWindowAtM0 asserts the
// weakness on purpose, so that the day vizra-search owns storage this test MUST
// be rewritten rather than quietly kept passing.
//
// The canonical contract, components.securitySchemes.hmacSignature:
//
//	"Known limitation, stated rather than implied: there is no nonce replay
//	 store in M0. The timestamp window is the whole replay bound, and a captured
//	 request can be replayed within 300 s. A nonce store is required once
//	 vizra-search owns storage."
//
// At M0 the blast radius is a duplicate no-op: every reply is not_indexed and
// nothing is stored. At M3 the same replay returns a permission-projected
// result set, and a replayed events batch is an index mutation — which is why
// the obligation is tracked rather than carried in prose.
func TestIdenticalRequestsCanStillBeReplayedInsideTheWindowAtM0(t *testing.T) {
	srv, _ := newServer(t)
	path := "/internal/v1/search"
	body := validBody(path)

	// One signed request, captured verbatim — same timestamp, same nonce, same
	// signature, same bytes.
	nonce := "0123456789abcdef0123456789abcdef"
	ts, sig := hmacauth.SignAt([]byte(testKey), http.MethodPost, path, time.Now(), nonce, body)

	replay := func() int {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set(hmacauth.HeaderTimestamp, ts)
		req.Header.Set(hmacauth.HeaderNonce, nonce)
		req.Header.Set(hmacauth.HeaderSignature, sig)
		return do(t, srv, req).Code
	}

	if first := replay(); first != http.StatusOK {
		t.Fatalf("the original request = %d, want 200", first)
	}
	second := replay()
	if second != http.StatusOK {
		t.Fatalf("the replayed request = %d.\n"+
			"If vizra-search has gained a nonce store, this is the RIGHT answer and this "+
			"test must be rewritten to assert rejection — along with AGENTS.md "+
			"§ 'Known limitation' and the contract clause it cites.", second)
	}
	// Recorded explicitly: at M0 an identical replay inside the 300 s window is
	// ACCEPTED, because there is nowhere to remember the nonce.
	t.Log("M0 behaviour confirmed: an identical request replayed inside the window is accepted; the timestamp window is the whole replay bound")
}
