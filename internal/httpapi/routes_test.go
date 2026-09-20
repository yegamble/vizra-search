package httpapi_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/hmacauth"
	"github.com/yegamble/vizra-search/internal/httpapi"
)

// provoke builds a request that must produce the given status on the given
// route. A status with no entry here cannot be claimed as emitted.
func provoke(t *testing.T, r httpapi.Route, status int) (*http.Request, func(*httpapi.Server)) {
	t.Helper()
	noSetup := func(*httpapi.Server) {}

	if r.Method == http.MethodGet {
		switch status {
		case http.StatusOK:
			return httptest.NewRequest(http.MethodGet, r.Path, nil), noSetup
		case http.StatusServiceUnavailable:
			// Readiness goes 503 once the process begins draining.
			return httptest.NewRequest(http.MethodGet, r.Path, nil), func(s *httpapi.Server) { s.BeginDrain() }
		}
		return nil, nil
	}

	switch status {
	case http.StatusOK:
		return signedRequest(t, r.Method, r.Path, validBody(r.Path)), noSetup
	case http.StatusBadRequest:
		return signedRequest(t, r.Method, r.Path, []byte(`{"query":`)), noSetup
	case http.StatusUnauthorized:
		return httptest.NewRequest(r.Method, r.Path, bytes.NewReader(validBody(r.Path))), noSetup
	case http.StatusRequestEntityTooLarge:
		return signedRequest(t, r.Method, r.Path, bytes.Repeat([]byte("a"), 8*smallBodyLimit)), noSetup
	case http.StatusServiceUnavailable:
		return signedRequest(t, r.Method, r.Path, validBody(r.Path)), func(s *httpapi.Server) { s.BeginDrain() }
	}
	return nil, nil
}

// TestEveryEmittedStatusIsReachable is what makes the route table honest. The
// contract drift check compares the table's status codes against the canonical
// document; if the table were maintained by hand it could claim a status the
// service never produces, and the drift check would be comparing two pieces of
// fiction. Every status classified as *emitted* is provoked here with a real
// request.
func TestEveryEmittedStatusIsReachable(t *testing.T) {
	table := httpapi.RouteTable()
	if len(table) == 0 {
		t.Fatal("the route table is empty")
	}
	for _, r := range table {
		if len(r.Emitted) == 0 {
			t.Errorf("%s %s emits no status at all", r.Method, r.Path)
		}
		for _, status := range r.Emitted {
			req, setup := provoke(t, r, status)
			if req == nil {
				t.Errorf("%s %s claims to emit %d, but this test has no way to provoke it; either the claim is false or this test needs a case", r.Method, r.Path, status)
				continue
			}
			srv, _ := newServer(t)
			setup(srv)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != status {
				t.Errorf("%s %s: provoking %d produced %d (%s)", r.Method, r.Path, status, rec.Code, rec.Body.String())
			}
		}
	}
}

// TestEveryNotEmittedStatusCarriesAReason keeps the escape hatch narrow: a
// status may be excluded from the reachability proof only with a written
// reason, which a reviewer sees in the diff.
func TestEveryNotEmittedStatusCarriesAReason(t *testing.T) {
	for _, r := range httpapi.RouteTable() {
		for status, reason := range r.DeclaredNotEmitted {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s %s declares %d as not emitted with no reason", r.Method, r.Path, status)
			}
			if len(reason) < 40 {
				t.Errorf("%s %s: the reason for not emitting %d is too terse to review: %q", r.Method, r.Path, status, reason)
			}
			for _, emitted := range r.Emitted {
				if emitted == status {
					t.Errorf("%s %s lists %d as both emitted and not emitted", r.Method, r.Path, status)
				}
			}
		}
	}
}

// TestRoutesMatchTheRegisteredHandlers guards the other direction inside this
// package: a route added to the router but forgotten in the table would escape
// the contract check entirely.
func TestRoutesMatchTheRegisteredHandlers(t *testing.T) {
	srv, _ := newServer(t)

	declared := map[string]bool{}
	for _, r := range httpapi.Routes() {
		declared[r.Key()] = true
		rec := httptest.NewRecorder()
		var req *http.Request
		if r.Method == http.MethodGet {
			req = httptest.NewRequest(r.Method, r.Path, nil)
		} else {
			req = signedRequest(t, r.Method, r.Path, validBody(r.Path))
		}
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("Routes() declares %s but the router does not serve it (%d)", r.Key(), rec.Code)
		}
	}

	// And no neighbouring path may be served. The router offers no
	// enumeration, so this probes the names an edit is likely to introduce.
	for _, candidate := range []string{
		"/internal/v1/suggest",
		"/internal/v1/search/",
		"/internal/v1/event",
		"/internal/v1/rerank",
		"/internal/v1/index",
		"/internal/v1/reconcile",
		"/internal/v1/status",
		"/internal/v2/search",
		"/metrics",
		"/debug/pprof/",
		"/schemaz",
	} {
		if declared[http.MethodPost+" "+candidate] || declared[http.MethodGet+" "+candidate] {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, signedRequest(t, method, candidate, []byte(`{}`)))
			if rec.Code != http.StatusNotFound {
				t.Errorf("the router serves %s %s, which the route table does not declare (%d)", method, candidate, rec.Code)
			}
		}
	}
}

func TestRoutesAreExactlyTheContractSurface(t *testing.T) {
	var keys []string
	seen := map[string]bool{}
	for _, r := range httpapi.Routes() {
		if r.OperationID == "" {
			t.Errorf("%s has no operationId", r.Key())
		}
		if seen[r.Key()] {
			t.Errorf("%s is declared twice", r.Key())
		}
		seen[r.Key()] = true
		keys = append(keys, r.Key())
	}
	sort.Strings(keys)
	want := []string{
		"GET /healthz",
		"GET /readyz",
		"GET /version",
		"POST /internal/v1/events",
		"POST /internal/v1/search",
		"POST /internal/v1/suggestions",
	}
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Fatalf("Routes() = %v, want exactly the Q-001 surface %v", keys, want)
	}
}

// A signature stays valid for the whole skew window, so a correctly signed
// request made a little in the past still works. This pins the window as
// behaviour rather than as a constant.
func TestSignatureRemainsValidInsideTheWindow(t *testing.T) {
	srv, _ := newServer(t)
	path := "/internal/v1/search"
	body := validBody(path)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	nonce := "0123456789abcdef0123456789abcdef"
	ts, sig := hmacauth.SignAt([]byte(testKey), http.MethodPost, path, time.Now().Add(-4*time.Minute), nonce, body)
	req.Header.Set(hmacauth.HeaderTimestamp, ts)
	req.Header.Set(hmacauth.HeaderNonce, nonce)
	req.Header.Set(hmacauth.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a 4-minute-old signature = %d, want 200 inside the 5-minute window", rec.Code)
	}
}
