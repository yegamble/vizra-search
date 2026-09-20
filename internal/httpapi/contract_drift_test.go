package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/config"
	"github.com/yegamble/vizra-search/internal/contract"
	"github.com/yegamble/vizra-search/internal/hmacauth"
	"github.com/yegamble/vizra-search/internal/httpapi"
)

// The canonical contract is owned by vizra-core and vendored here byte for
// byte. This repository never edits it; a change lands in core first and turns
// this check red until it is vendored again.
const (
	contractPath = "../../api/search-internal.openapi.yaml"
	vectorsPath  = "../../api/search-hmac-testvectors.json"
	manifestPath = "../../api/CONTRACT-SOURCE.json"
)

// contractManifest mirrors api/CONTRACT-SOURCE.json. It records EVERY vendored
// file, because the contract is now two files — the OpenAPI document and the
// normative HMAC conformance vectors — and a manifest that pinned only one of
// them would leave the other editable in place.
type contractManifest struct {
	SourceRepository string         `json:"source_repository"`
	SourceRef        string         `json:"source_ref"`
	SourceCommit     string         `json:"source_commit"`
	Files            []manifestFile `json:"files"`
}

type manifestFile struct {
	SourcePath   string `json:"source_path"`
	VendoredPath string `json:"vendored_path"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	Role         string `json:"role"`
}

func loadManifest(t *testing.T) contractManifest {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading %s: %v", manifestPath, err)
	}
	var m contractManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s is not JSON: %v", manifestPath, err)
	}
	return m
}

func loadContract(t *testing.T) *contract.Doc {
	t.Helper()
	doc, err := contract.Load(contractPath)
	if err != nil {
		t.Fatalf("loading the canonical contract: %v", err)
	}
	return doc
}

// TestEveryVendoredFileMatchesItsManifest proves no vendored copy has been
// edited in place. Without this, a developer could "fix" a drift failure by
// changing the contract in this repository — which is exactly the failure mode
// a two-repository drift check exists to prevent. Both files are checked: the
// OpenAPI document and the normative HMAC conformance vectors.
func TestEveryVendoredFileMatchesItsManifest(t *testing.T) {
	m := loadManifest(t)

	if m.SourceRepository != "yegamble/vizra-core" {
		t.Errorf("source_repository = %q; vizra-core owns this contract (ADR-002, Q-001)", m.SourceRepository)
	}
	if len(m.SourceCommit) != 40 {
		t.Errorf("source_commit = %q, want a full 40-character commit SHA so the consumed version is unambiguous", m.SourceCommit)
	}

	// Both files must be pinned. A manifest that silently stopped listing one
	// of them would leave that file editable with CI green.
	want := map[string]bool{
		"api/search-internal.openapi.yaml": false,
		"api/search-hmac-testvectors.json": false,
	}
	for _, f := range m.Files {
		key := filepath.ToSlash(f.VendoredPath)
		if _, expected := want[key]; expected {
			want[key] = true
		}
		if f.SourcePath != key {
			t.Errorf("%s: source_path %q differs from vendored_path %q; the vendored copy must sit at the same path as in core", key, f.SourcePath, key)
		}

		raw, err := os.ReadFile("../../" + key)
		if err != nil {
			t.Errorf("reading the vendored %s: %v", key, err)
			continue
		}
		if got := contract.Digest(raw); got != f.SHA256 {
			t.Errorf("the vendored %s does not match its manifest.\n  manifest sha256: %s\n  file sha256:     %s\n"+
				"This repository does not own it. Re-vendor from %s@%s instead of editing it.",
				key, f.SHA256, got, m.SourceRepository, m.SourceCommit)
		}
		if int64(len(raw)) != f.Bytes {
			t.Errorf("the vendored %s is %d bytes, the manifest says %d", key, len(raw), f.Bytes)
		}
		if strings.TrimSpace(f.Role) == "" {
			t.Errorf("%s carries no role in the manifest", key)
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("the manifest no longer pins %s, so that file could be edited in place with CI green", key)
		}
	}
}

// TestNoDriftFromTheCanonicalContract is demonstration D1. It fails in both
// directions: an operation in the contract with no route here, and a route here
// with no operation in the contract. It also compares operation ids and the
// declared response status codes.
func TestNoDriftFromTheCanonicalContract(t *testing.T) {
	doc := loadContract(t)
	diff := doc.Compare(httpapi.Routes())
	if err := diff.Err(); err != nil {
		t.Fatalf("%v\n\nThe canonical copy lives in vizra-core. If the contract is wrong, change it there and re-vendor; do not edit %s.", err, contractPath)
	}
}

// TestTheContractStillDeclaresTheQ001Surface guards against the contract
// itself being emptied out. A drift check that passes because the contract
// declares nothing is not a check.
func TestTheContractStillDeclaresTheQ001Surface(t *testing.T) {
	doc := loadContract(t)
	want := map[string]bool{
		"GET /healthz":                  false,
		"GET /readyz":                   false,
		"GET /version":                  false,
		"POST /internal/v1/search":      false,
		"POST /internal/v1/suggestions": false,
		"POST /internal/v1/events":      false,
	}
	for _, op := range doc.Operations {
		if _, expected := want[op.Key()]; expected {
			want[op.Key()] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("the canonical contract no longer declares %s, which Q-001 requires", key)
		}
	}
}

// TestEveryInternalOperationIsSecured proves the contract still demands a
// signature on every internal operation, and that the probes still do not.
func TestEveryInternalOperationIsSecured(t *testing.T) {
	doc := loadContract(t)
	for _, op := range doc.Operations {
		internal := len(op.Path) >= len(contract.InternalPrefix) && op.Path[:len(contract.InternalPrefix)] == contract.InternalPrefix
		if internal && !op.Secured {
			t.Errorf("%s declares no security requirement; every internal operation is HMAC-authenticated (Q-001)", op.Key())
		}
		if !internal && op.Secured {
			t.Errorf("%s is a probe and must stay unauthenticated so an orchestrator can call it", op.Key())
		}
	}
}

// TestResponseBodiesSatisfyTheContractSchemas is the field-level half of the
// drift check. Every schema in this contract sets additionalProperties: false,
// so a renamed, added or dropped response field fails here.
func TestResponseBodiesSatisfyTheContractSchemas(t *testing.T) {
	doc := loadContract(t)

	for _, r := range httpapi.RouteTable() {
		for _, status := range r.Emitted {
			name := r.Method + " " + r.Path + " -> " + http.StatusText(status)
			t.Run(name, func(t *testing.T) {
				req, setup := provoke(t, r, status)
				if req == nil {
					t.Fatalf("no provoker for %d", status)
				}
				srv, _ := newServer(t)
				setup(srv)
				rec := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, req)
				if rec.Code != status {
					t.Fatalf("expected %d, got %d (%s)", status, rec.Code, rec.Body.String())
				}
				if err := doc.ValidateResponse(r.Method, r.Path, status, rec.Body.Bytes()); err != nil {
					t.Fatalf("the response body violates the canonical contract: %v\nbody: %s", err, rec.Body.String())
				}
			})
		}
	}
}

// TestTheContractSchemasActuallyRejectDrift proves the validator is not a
// no-op: a body with a renamed field, a missing required field or an
// out-of-enum value must be rejected.
func TestTheContractSchemasActuallyRejectDrift(t *testing.T) {
	doc := loadContract(t)

	good := `{"status":"not_indexed","results":[],"total":0,"search_schema_version":null}`
	if err := doc.Validate("SearchResponse", []byte(good)); err != nil {
		t.Fatalf("the validator rejected a conforming body: %v", err)
	}

	for name, body := range map[string]string{
		"a renamed field":                  `{"status":"not_indexed","hits":[],"total":0}`,
		"an added field":                   `{"status":"not_indexed","results":[],"total":0,"reason":"no index"}`,
		"a missing required field":         `{"status":"not_indexed","results":[]}`,
		"an out-of-enum status":            `{"status":"empty","results":[],"total":0}`,
		"a wrongly typed total":            `{"status":"not_indexed","results":[],"total":"0"}`,
		"a null in a non-nullable":         `{"status":null,"results":[],"total":0}`,
		"an array where an object belongs": `[]`,
	} {
		if err := doc.Validate("SearchResponse", []byte(body)); err == nil {
			t.Errorf("the validator accepted %s: %s", name, body)
		}
	}

	// The same for the error shape, since every rejection uses it.
	if err := doc.Validate("Error", []byte(`{"error":{"code":"signature_rejected","message":"no"}}`)); err != nil {
		t.Fatalf("the validator rejected a conforming Error: %v", err)
	}
	for name, body := range map[string]string{
		"an undeclared code": `{"error":{"code":"nope","message":"x"}}`,
		"a missing message":  `{"error":{"code":"bad_request"}}`,
		"an extra field":     `{"error":{"code":"bad_request","message":"x"},"reason":"y"}`,
	} {
		if err := doc.Validate("Error", []byte(body)); err == nil {
			t.Errorf("the validator accepted %s in an Error body", name)
		}
	}
}

// TestRejectionBodiesUseTheContractErrorShape checks the negative paths the
// reachability test provokes, at the body level.
func TestRejectionBodiesUseTheContractErrorShape(t *testing.T) {
	doc := loadContract(t)
	srv, _ := newServer(t)

	cases := []struct {
		name string
		req  *http.Request
	}{
		{"unsigned", httptest.NewRequest(http.MethodPost, "/internal/v1/search", bytes.NewReader(validBody("/internal/v1/search")))},
		{"malformed body", signedRequest(t, http.MethodPost, "/internal/v1/search", []byte(`{"query":`))},
		{"oversized", signedRequest(t, http.MethodPost, "/internal/v1/search", bytes.Repeat([]byte("a"), 8*smallBodyLimit))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, tc.req)
			if err := doc.Validate("Error", rec.Body.Bytes()); err != nil {
				t.Fatalf("the %d body is not the contract's Error shape: %v\nbody: %s", rec.Code, err, rec.Body.String())
			}
		})
	}
}

// TestTheContractsFixedNumbersMatchTheImplementation reads the two numbers the
// contract owns out of the vendored document itself, rather than asserting a
// constant against itself. A change to either number in vizra-core then turns
// this repository red the way a renamed route already does.
func TestTheContractsFixedNumbersMatchTheImplementation(t *testing.T) {
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("reading the vendored contract: %v", err)
	}
	text := string(raw)

	// "the skew is then computed on plain int64 seconds against a window of
	// ±300 s." — the phrase wraps in the YAML block scalar, so the token is
	// matched rather than the sentence.
	if !strings.Contains(text, "±300 s") {
		t.Errorf("the contract no longer states a ±300 s window; config.DefaultMaxClockSkew is %v and may need to follow", config.DefaultMaxClockSkew)
	}
	if config.DefaultMaxClockSkew != 300*time.Second {
		t.Errorf("DefaultMaxClockSkew = %v, the contract fixes 300 s", config.DefaultMaxClockSkew)
	}

	// "A body above `MAX_INTERNAL_BODY_BYTES` (default 1 MiB)"
	if !strings.Contains(text, "`MAX_INTERNAL_BODY_BYTES` (default 1 MiB)") {
		t.Errorf("the contract no longer states a 1 MiB default body cap; config.DefaultMaxBodyBytes is %d and may need to follow", config.DefaultMaxBodyBytes)
	}
	if config.DefaultMaxBodyBytes != 1<<20 {
		t.Errorf("DefaultMaxBodyBytes = %d, the contract fixes 1 MiB", config.DefaultMaxBodyBytes)
	}

	// The absolute magnitude range, which is what closes the window.
	for _, want := range []string{"1000000000", "4102444800"} {
		if !strings.Contains(text, want) {
			t.Errorf("the contract no longer names the absolute timestamp bound %s", want)
		}
	}
	if hmacauth.MinTimestampUnix != 1000000000 || hmacauth.MaxTimestampUnix != 4102444800 {
		t.Errorf("the implementation's absolute range is [%d, %d], the contract fixes [1000000000, 4102444800]",
			hmacauth.MinTimestampUnix, hmacauth.MaxTimestampUnix)
	}

	// The nonce ceiling.
	if !strings.Contains(text, "at most 128") {
		t.Error("the contract no longer states the 128-character nonce ceiling")
	}
	if hmacauth.MaxNonceHexLen != 128 {
		t.Errorf("MaxNonceHexLen = %d, the contract fixes 128", hmacauth.MaxNonceHexLen)
	}
}

// The vendored vectors must parse and must still carry both halves. A vector
// file trimmed to its ACCEPT cases would leave the reject set — the half the
// contract says matters more — unchecked.
func TestTheVendoredVectorsAreUsable(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("reading the vendored vectors: %v", err)
	}
	var vf struct {
		Vectors         []json.RawMessage `json:"vectors"`
		NegativeVectors []json.RawMessage `json:"negative_vectors"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("the vendored vectors are not JSON: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Error("the vendored vectors declare no ACCEPT cases")
	}
	if len(vf.NegativeVectors) < 20 {
		t.Errorf("the vendored vectors declare only %d REJECT cases; the reject set is the half that catches divergence", len(vf.NegativeVectors))
	}
}
