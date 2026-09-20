package httpapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
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

const testKey = "9f2c1d7a4b3e6f80c5a91d2e3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"

// smallBodyLimit keeps the 413 case cheap. Production defaults to 1 MiB.
const smallBodyLimit = 1024

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadFrom(func(key string) (string, bool) {
		switch key {
		case config.EnvMode:
			return "production", true
		case config.EnvHMACKey:
			return testKey, true
		case config.EnvMaxBodyBytes:
			return "1024", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("config.LoadFrom: %v", err)
	}
	return cfg
}

func newServer(t *testing.T) (*httpapi.Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	return httpapi.New(testConfig(t), httpapi.NewLogger(&logs)), &logs
}

// validBody returns a request body that satisfies the contract's request
// schema for the given endpoint.
func validBody(path string) []byte {
	switch path {
	case "/internal/v1/search":
		return []byte(`{"query":"sunset","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`)
	case "/internal/v1/suggestions":
		return []byte(`{"prefix":"sun","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`)
	case "/internal/v1/events":
		return []byte(`{"site":{"handle":"default"},"events":[{"event_id":"11111111-1111-4111-8111-111111111111","kind":"upsert","occurred_at":"2026-09-20T00:00:00Z","subject_type":"asset","subject_id":"22222222-2222-4222-8222-222222222222"}]}`)
	default:
		return []byte(`{}`)
	}
}

func signedRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := hmacauth.SignRequest([]byte(testKey), req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return req
}

// signedAt signs with an explicit time and nonce, for the stale-timestamp case.
func signedAt(t *testing.T, key []byte, method, path string, at time.Time, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	nonce := "0123456789abcdef0123456789abcdef"
	ts, sig := hmacauth.Sign(key, method, path, at, nonce, body)
	req.Header.Set(hmacauth.HeaderTimestamp, ts)
	req.Header.Set(hmacauth.HeaderNonce, nonce)
	req.Header.Set(hmacauth.HeaderSignature, sig)
	return req
}

func do(t *testing.T, srv *httpapi.Server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response body is not JSON (%d): %q", rec.Code, rec.Body.String())
	}
	return out
}

var internalPaths = []string{
	"/internal/v1/search",
	"/internal/v1/suggestions",
	"/internal/v1/events",
}

// ---------------------------------------------------------------- probes ---

func TestHealthzIsLivenessOnly(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(t, srv, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", rec.Code)
	}
	if got := decode(t, rec)["status"]; got != "ok" {
		t.Fatalf("/healthz status = %v", got)
	}
}

func TestProbesRequireNoSignature(t *testing.T) {
	// The probes are unauthenticated by contract (security: []): an
	// orchestrator must be able to call them without the shared secret, so
	// they expose nothing beyond build identity and component state.
	srv, _ := newServer(t)
	for _, path := range []string{"/healthz", "/readyz", "/version"} {
		rec := do(t, srv, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s demanded a signature", path)
		}
	}
}

func TestReadyzIsReadyWithNoComponents(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(t, srv, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	if body["status"] != "ok" {
		t.Fatalf("/readyz status = %v, want ok", body["status"])
	}
	components, ok := body["components"].([]any)
	if !ok {
		t.Fatalf("/readyz components is not an array: %v", body["components"])
	}
	// This service holds no database at M0. An empty array is the honest
	// answer; a fabricated healthy component would not be.
	if len(components) != 0 {
		t.Fatalf("/readyz reports %d components while it owns no dependency", len(components))
	}
	if _, err := time.Parse(time.RFC3339, body["checked_at"].(string)); err != nil {
		t.Fatalf("checked_at is not RFC 3339: %v", body["checked_at"])
	}
}

func TestReadyzIsDrainAware(t *testing.T) {
	// ADR-002 § Probes: /readyz is drain-aware. Liveness must stay 200 while
	// readiness goes 503, so an orchestrator stops routing without killing a
	// process that is still finishing requests.
	srv, _ := newServer(t)
	srv.BeginDrain()

	rec := do(t, srv, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining /readyz = %d, want 503", rec.Code)
	}
	if got := decode(t, rec)["status"]; got != "unavailable" {
		t.Fatalf("draining /readyz status = %v, want unavailable", got)
	}

	live := do(t, srv, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("draining /healthz = %d, want 200 (liveness only)", live.Code)
	}
}

func TestDrainingInternalCallsAreAFaultNotAnEmptyIndex(t *testing.T) {
	// Q-001 forbids a silent fallback. A draining process must look like a
	// fault to core — so core reports search: degraded — and must not look
	// like a healthy empty index.
	srv, _ := newServer(t)
	srv.BeginDrain()
	for _, path := range internalPaths {
		rec := do(t, srv, signedRequest(t, http.MethodPost, path, validBody(path)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("draining %s = %d, want 503", path, rec.Code)
		}
		body := decode(t, rec)
		if body["status"] == "not_indexed" {
			t.Fatalf("draining %s answered not_indexed; core would record a healthy empty index instead of a fault", path)
		}
	}
}

func TestVersionReportsNoSearchSchemaVersion(t *testing.T) {
	// Q-001: "it reports no search_schema_version until it owns migrations."
	// The field must be present and explicitly null — not omitted, not 0, not
	// a string — so core can tell "no schema yet" from "field missing".
	srv, _ := newServer(t)
	rec := do(t, srv, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/version = %d", rec.Code)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("/version is not JSON: %v", err)
	}
	value, present := raw["search_schema_version"]
	if !present {
		t.Fatal("/version omits search_schema_version; it must be present and null")
	}
	if string(value) != "null" {
		t.Fatalf("search_schema_version = %s, want null (this service owns no migrations yet)", value)
	}
	for _, field := range []string{"release", "commit", "built_at", "go_version"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("/version omits %q", field)
		}
	}
}

func TestReadyzAlsoReportsNoSearchSchemaVersion(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(t, srv, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if string(raw["search_schema_version"]) != "null" {
		t.Fatalf("search_schema_version = %s, want null", raw["search_schema_version"])
	}
}

// ----------------------------------------------- internal endpoints: happy ---

func TestInternalEndpointsAnswerNotIndexed(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			rec := do(t, srv, signedRequest(t, http.MethodPost, path, validBody(path)))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s = %d (%s), want 200", path, rec.Code, rec.Body.String())
			}
			if got := decode(t, rec)["status"]; got != "not_indexed" {
				t.Fatalf("%s status = %v, want the explicit not_indexed of Q-001", path, got)
			}
		})
	}
}

func TestSearchAndSuggestionsReturnEmptyCollections(t *testing.T) {
	srv, _ := newServer(t)
	for _, tc := range []struct{ path, field string }{
		{"/internal/v1/search", "results"},
		{"/internal/v1/suggestions", "suggestions"},
	} {
		rec := do(t, srv, signedRequest(t, http.MethodPost, tc.path, validBody(tc.path)))
		body := decode(t, rec)
		items, ok := body[tc.field].([]any)
		if !ok {
			t.Fatalf("%s has no %q array: %v", tc.path, tc.field, body)
		}
		if len(items) != 0 {
			t.Fatalf("%s returned %d items while not indexed", tc.path, len(items))
		}
	}
	rec := do(t, srv, signedRequest(t, http.MethodPost, "/internal/v1/search", validBody("/internal/v1/search")))
	if total := decode(t, rec)["total"].(float64); total != 0 {
		t.Fatalf("total = %v, want 0 when not indexed", total)
	}
}

func TestEventsAcceptsNothingAndSaysSo(t *testing.T) {
	// Storing events is out of scope for this slice. accepted:0 tells core the
	// batch was deliberately discarded, so core marks the job succeeded rather
	// than retrying forever — and it does not pretend an event was stored.
	srv, _ := newServer(t)
	rec := do(t, srv, signedRequest(t, http.MethodPost, "/internal/v1/events", validBody("/internal/v1/events")))
	if rec.Code != http.StatusOK {
		t.Fatalf("/internal/v1/events = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if body["status"] != "not_indexed" {
		t.Fatalf("status = %v", body["status"])
	}
	if got := body["accepted"].(float64); got != 0 {
		t.Fatalf("accepted = %v, want 0 (this slice stores nothing)", got)
	}
	if got := body["duplicates"].(float64); got != 0 {
		t.Fatalf("duplicates = %v, want 0", got)
	}
}

func TestInternalResponsesNeverLeakTheKey(t *testing.T) {
	srv, logs := newServer(t)
	for _, path := range internalPaths {
		rec := do(t, srv, signedRequest(t, http.MethodPost, path, validBody(path)))
		if strings.Contains(rec.Body.String(), testKey) {
			t.Fatalf("%s response leaks the shared secret", path)
		}
	}
	if strings.Contains(logs.String(), testKey) {
		t.Fatal("the log leaks the shared secret")
	}
}

// -------------------------------------------- internal endpoints: negative ---

// wantSignatureRejected asserts the contract's rejection shape: always 401
// with code signature_rejected, and never a hint about which header was wrong.
func wantSignatureRejected(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s = %d (%s), want 401", what, rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	detail, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("%s: response has no error object: %v", what, body)
	}
	if detail["code"] != "signature_rejected" {
		t.Fatalf("%s: code = %v, want signature_rejected", what, detail["code"])
	}
	// The contract: "MUST NOT say which of the three headers was wrong."
	message := strings.ToLower(detail["message"].(string))
	for _, forbidden := range []string{"timestamp", "nonce", "signature is", "stale", "missing", "malformed"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("%s: the rejection message %q names the failing header, which the contract forbids", what, message)
		}
	}
}

func TestUnsignedRequestsAreRejected(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(validBody(path)))
			wantSignatureRejected(t, do(t, srv, req), "unsigned "+path)
		})
	}
}

func TestWronglySignedRequestsAreRejected(t *testing.T) {
	srv, _ := newServer(t)
	wrongKey := []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			body := validBody(path)
			req := signedAt(t, wrongKey, http.MethodPost, path, time.Now(), body)
			wantSignatureRejected(t, do(t, srv, req), "wrongly signed "+path)
		})
	}
}

func TestStaleTimestampsAreRejected(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			stale := time.Now().Add(-config.DefaultMaxClockSkew - time.Minute)
			req := signedAt(t, []byte(testKey), http.MethodPost, path, stale, validBody(path))
			wantSignatureRejected(t, do(t, srv, req), "stale "+path)
		})
	}
}

func TestFutureTimestampsAreRejected(t *testing.T) {
	srv, _ := newServer(t)
	future := time.Now().Add(config.DefaultMaxClockSkew + time.Minute)
	req := signedAt(t, []byte(testKey), http.MethodPost, "/internal/v1/search", future, validBody("/internal/v1/search"))
	wantSignatureRejected(t, do(t, srv, req), "future-dated")
}

func TestMissingNonceIsRejected(t *testing.T) {
	srv, _ := newServer(t)
	req := signedRequest(t, http.MethodPost, "/internal/v1/search", validBody("/internal/v1/search"))
	req.Header.Del(hmacauth.HeaderNonce)
	wantSignatureRejected(t, do(t, srv, req), "nonce-less")
}

func TestTamperedBodiesAreRejected(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range internalPaths {
		t.Run(path, func(t *testing.T) {
			signed := validBody(path)
			tampered := append(append([]byte(nil), signed[:len(signed)-1]...), []byte(`,"extra":1}`)...)
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(tampered))
			nonce := "0123456789abcdef0123456789abcdef"
			// Sign the original body, send the tampered one.
			ts, sig := hmacauth.Sign([]byte(testKey), http.MethodPost, path, time.Now(), nonce, signed)
			req.Header.Set(hmacauth.HeaderTimestamp, ts)
			req.Header.Set(hmacauth.HeaderNonce, nonce)
			req.Header.Set(hmacauth.HeaderSignature, sig)
			wantSignatureRejected(t, do(t, srv, req), "tampered "+path)
		})
	}
}

func TestASignatureForOneEndpointDoesNotOpenAnother(t *testing.T) {
	srv, _ := newServer(t)
	body := validBody("/internal/v1/events")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/events", bytes.NewReader(body))
	nonce := "0123456789abcdef0123456789abcdef"
	ts, sig := hmacauth.Sign([]byte(testKey), http.MethodPost, "/internal/v1/search", time.Now(), nonce, body)
	req.Header.Set(hmacauth.HeaderTimestamp, ts)
	req.Header.Set(hmacauth.HeaderNonce, nonce)
	req.Header.Set(hmacauth.HeaderSignature, sig)
	wantSignatureRejected(t, do(t, srv, req), "cross-endpoint replay")
}

func TestRejectionsCarryNoResultShape(t *testing.T) {
	// A 401 must not look like a successful not_indexed answer, or core's
	// fallback logic could mistake a misconfiguration for an empty index.
	srv, _ := newServer(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/search", strings.NewReader(`{}`))
	body := decode(t, do(t, srv, req))
	if body["status"] == "not_indexed" {
		t.Fatal("an unauthorized response reports not_indexed; core would treat a rejected call as an empty index")
	}
	if _, ok := body["results"]; ok {
		t.Fatal("an unauthorized response carries a results field")
	}
}

func TestMalformedAndIncompleteRequestsAre400(t *testing.T) {
	srv, _ := newServer(t)
	cases := []struct {
		name, path string
		body       string
	}{
		{"truncated json", "/internal/v1/search", `{"query":`},
		{"not an object", "/internal/v1/search", `[]`},
		{"empty body", "/internal/v1/search", ``},
		{"missing query", "/internal/v1/search", `{"viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`},
		{"missing viewer", "/internal/v1/search", `{"query":"x","site":{"handle":"default"}}`},
		{"missing site", "/internal/v1/search", `{"query":"x","viewer":{"is_anonymous":true,"role":"anonymous"}}`},
		{"viewer without role", "/internal/v1/search", `{"query":"x","viewer":{"is_anonymous":true},"site":{"handle":"default"}}`},
		{"missing prefix", "/internal/v1/suggestions", `{"viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`},
		{"empty prefix", "/internal/v1/suggestions", `{"prefix":"","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`},
		{"empty event batch", "/internal/v1/events", `{"site":{"handle":"default"},"events":[]}`},
		{"events without site", "/internal/v1/events", `{"events":[{"event_id":"x"}]}`},
		{"trailing content", "/internal/v1/search", `{"query":"x","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}} {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, signedRequest(t, http.MethodPost, tc.path, []byte(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d (%s), want 400", tc.name, rec.Code, rec.Body.String())
			}
			detail := decode(t, rec)["error"].(map[string]any)
			if detail["code"] != "bad_request" {
				t.Fatalf("code = %v, want bad_request", detail["code"])
			}
		})
	}
}

func TestOversizedBodiesAreRefused(t *testing.T) {
	srv, _ := newServer(t)
	huge := bytes.Repeat([]byte("a"), 4*smallBodyLimit)
	for _, path := range internalPaths {
		rec := do(t, srv, signedRequest(t, http.MethodPost, path, huge))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized %s = %d, want 413", path, rec.Code)
		}
		detail := decode(t, rec)["error"].(map[string]any)
		if detail["code"] != "payload_too_large" {
			t.Fatalf("code = %v, want payload_too_large", detail["code"])
		}
	}
}

func TestAnOversizedBodyIsRefusedBeforeAuthentication(t *testing.T) {
	// The contract requires 413 *before* reading the body, so an unsigned
	// flood is cut off without buffering it.
	srv, _ := newServer(t)
	huge := bytes.Repeat([]byte("a"), 4*smallBodyLimit)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/search", bytes.NewReader(huge))
	rec := do(t, srv, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unsigned oversized request = %d, want 413 (the bound precedes authentication)", rec.Code)
	}
}

func TestADeclaredContentLengthAboveTheLimitIsRefusedWithoutAByteRead(t *testing.T) {
	srv, _ := newServer(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/search", &explodingReader{t: t})
	req.ContentLength = 4 * smallBodyLimit
	rec := do(t, srv, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("= %d, want 413", rec.Code)
	}
}

// explodingReader fails the test if anything reads from it.
type explodingReader struct{ t *testing.T }

func (r *explodingReader) Read([]byte) (int, error) {
	r.t.Error("the body was read even though Content-Length already exceeded the limit")
	return 0, io.EOF
}

func TestBodyExactlyAtTheLimitIsAccepted(t *testing.T) {
	srv, _ := newServer(t)
	prefix := `{"query":"`
	suffix := `","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`
	filler := strings.Repeat("a", smallBodyLimit-len(prefix)-len(suffix))
	body := []byte(prefix + filler + suffix)
	if len(body) != smallBodyLimit {
		t.Fatalf("fixture error: body is %d bytes", len(body))
	}
	rec := do(t, srv, signedRequest(t, http.MethodPost, "/internal/v1/search", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("a body exactly at the limit = %d (%s), want 200", rec.Code, rec.Body.String())
	}
}

func TestWrongMethodsAreRefused(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range internalPaths {
		rec := do(t, srv, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d, want 405", path, rec.Code)
		}
	}
}

func TestUnknownPathsAre404(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(t, srv, signedRequest(t, http.MethodPost, "/internal/v1/rerank", []byte(`{}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", rec.Code)
	}
}

// ----------------------------------------------------------- cross-cutting ---

func TestHandlersReceiveABoundedDeadline(t *testing.T) {
	// AGENTS.md § Engineering guardrails: propagate cancellation/deadlines.
	srv, _ := newServer(t)
	rec := do(t, srv, signedRequest(t, http.MethodPost, "/internal/v1/search", validBody("/internal/v1/search")))
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: %d (%s)", rec.Code, rec.Body.String())
	}
	deadline, ok := srv.LastRequestDeadline()
	if !ok {
		t.Fatal("the handler's request context carried no deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > config.DefaultRequestTimeout {
		t.Fatalf("deadline is %v away, want (0, %v]", remaining, config.DefaultRequestTimeout)
	}
}

func TestLogsNeverCarrySignatureMaterial(t *testing.T) {
	// ADR-002 § Logging and redaction.
	srv, logs := newServer(t)
	body := []byte(`{"query":"secret-term","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`)
	req := signedRequest(t, http.MethodPost, "/internal/v1/search", body)
	sig := req.Header.Get(hmacauth.HeaderSignature)
	nonce := req.Header.Get(hmacauth.HeaderNonce)
	do(t, srv, req)
	out := logs.String()
	if out == "" {
		t.Fatal("nothing was logged, so the redaction claim is untested")
	}
	for name, value := range map[string]string{
		"the request signature": sig,
		"the request nonce":     nonce,
		"the shared secret":     testKey,
		"the request body":      "secret-term",
	} {
		if strings.Contains(out, value) {
			t.Errorf("log carries %s: %s", name, out)
		}
	}
}

func TestResponsesAreJSON(t *testing.T) {
	srv, _ := newServer(t)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/healthz", nil),
		httptest.NewRequest(http.MethodGet, "/readyz", nil),
		httptest.NewRequest(http.MethodGet, "/version", nil),
		signedRequest(t, http.MethodPost, "/internal/v1/search", validBody("/internal/v1/search")),
		httptest.NewRequest(http.MethodPost, "/internal/v1/search", nil),
		httptest.NewRequest(http.MethodGet, "/nope", nil),
	} {
		rec := do(t, srv, req)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s %s Content-Type = %q", req.Method, req.URL.Path, ct)
		}
	}
}

// TestErrorHandlerRendersTheContractErrorShape covers the 500 path, which no
// request can provoke at M0 (see httpapi.reasonNo500). The route table records
// 500 as declared-but-not-emitted; this test proves the renderer for it exists
// and produces the contract's Error shape.
func TestErrorHandlerRendersTheContractErrorShape(t *testing.T) {
	srv, _ := newServer(t)
	rec := httptest.NewRecorder()
	srv.RenderErrorForTest(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/search", nil),
		errors.New("a dependency exploded"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("= %d, want 500", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %s", rec.Body.String())
	}
	detail, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error object: %v", body)
	}
	if detail["code"] != "internal_error" {
		t.Fatalf("code = %v, want internal_error", detail["code"])
	}
	if strings.Contains(rec.Body.String(), "exploded") {
		t.Fatalf("the 500 body leaks the internal error text: %s", rec.Body.String())
	}
}

func TestServerRefusesAnUnusableConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted a nil config")
		}
	}()
	httpapi.New(nil, httpapi.NewLogger(io.Discard))
}
