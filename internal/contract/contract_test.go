package contract_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/yegamble/vizra-search/internal/contract"
)

func loadGood(t *testing.T) *contract.Doc {
	t.Helper()
	doc, err := contract.Load("testdata/good.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return doc
}

func TestParseReadsEveryOperation(t *testing.T) {
	doc := loadGood(t)
	var keys []string
	for _, op := range doc.Operations {
		keys = append(keys, op.Key())
	}
	want := []string{"GET /healthz", "POST /internal/v1/events", "POST /internal/v1/search"}
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Fatalf("operations = %v, want %v", keys, want)
	}
}

func TestParseRecordsTheSecurityRequirement(t *testing.T) {
	for _, op := range loadGood(t).Operations {
		internal := strings.HasPrefix(op.Path, contract.InternalPrefix)
		if op.Secured != internal {
			t.Errorf("%s Secured = %v, want %v", op.Key(), op.Secured, internal)
		}
	}
}

func TestParseFollowsAResponseRefToItsSchema(t *testing.T) {
	doc := loadGood(t)
	name, ok := doc.ResponseSchemaFor("POST", "/internal/v1/search", 401)
	if !ok {
		t.Fatal("the 401 response, which is a $ref into components/responses, was not resolved")
	}
	if name != "Err" {
		t.Fatalf("schema = %q, want Err", name)
	}
}

func TestParseRefusesWildcardStatusCodes(t *testing.T) {
	// A wildcard would make the status comparison meaningless, so it is a
	// parse failure rather than a silently-skipped operation.
	_, err := contract.Load("testdata/wildcard.yaml")
	if err == nil {
		t.Fatal("Load accepted a 4XX wildcard response code")
	}
	if !errors.Is(err, contract.ErrContract) {
		t.Fatalf("error %v is not ErrContract", err)
	}
	if !strings.Contains(err.Error(), "4XX") {
		t.Fatalf("error %q does not name the offending code", err.Error())
	}
}

func TestParseRefusesADocumentWithNoInternalOperations(t *testing.T) {
	// If core ever removes the internal paths, this repository must fail
	// loudly rather than report "no drift".
	_, err := contract.Load("testdata/no-internal-paths.yaml")
	if err == nil {
		t.Fatal("Load accepted a document with no /internal/v1/ operations")
	}
	if !strings.Contains(err.Error(), contract.InternalPrefix) {
		t.Fatalf("error %q does not name the prefix", err.Error())
	}
}

func TestParseRefusesGarbage(t *testing.T) {
	for name, data := range map[string]string{
		"not yaml":         "\t\x00 not: [valid",
		"no openapi field": "info:\n  title: x\npaths:\n  /internal/v1/search:\n    post: {}\n",
		"no paths":         "openapi: 3.0.3\ninfo:\n  title: x\n",
		"empty":            "",
	} {
		if _, err := contract.Parse([]byte(data)); err == nil {
			t.Errorf("Parse accepted %s", name)
		}
	}
}

func TestParseRefusesAnOperationWithNoResponses(t *testing.T) {
	_, err := contract.Parse([]byte("openapi: 3.0.3\npaths:\n  /internal/v1/search:\n    post:\n      operationId: x\n"))
	if err == nil {
		t.Fatal("Parse accepted an operation with no declared responses")
	}
}

func TestParseRefusesAnOperationWithNoOperationID(t *testing.T) {
	_, err := contract.Parse([]byte("openapi: 3.0.3\npaths:\n  /internal/v1/search:\n    post:\n      responses:\n        \"200\": {description: ok}\n"))
	if err == nil {
		t.Fatal("Parse accepted an operation with no operationId")
	}
}

func implOf(ops ...contract.Operation) []contract.Operation { return ops }

func fullImplementation() []contract.Operation {
	return implOf(
		contract.Operation{Method: "GET", Path: "/healthz", OperationID: "fixtureHealth", Statuses: []int{200}},
		contract.Operation{Method: "POST", Path: "/internal/v1/search", OperationID: "fixtureSearch", Statuses: []int{401, 200}},
		contract.Operation{Method: "POST", Path: "/internal/v1/events", OperationID: "fixtureEvents", Statuses: []int{200, 401}},
	)
}

func TestCompareReportsNoDriftWhenTheyMatch(t *testing.T) {
	diff := loadGood(t).Compare(fullImplementation())
	if !diff.Empty() {
		t.Fatalf("unexpected drift: %v", diff.Err())
	}
	if diff.Err() != nil {
		t.Fatalf("Err() = %v on an empty diff", diff.Err())
	}
}

// Direction 1: the contract declares an operation this service does not serve.
func TestCompareDetectsAMissingRoute(t *testing.T) {
	impl := fullImplementation()[:2]
	diff := loadGood(t).Compare(impl)
	if diff.Empty() {
		t.Fatal("Compare reported no drift when a declared operation has no route")
	}
	if len(diff.DeclaredButNotImplemented) != 1 || diff.DeclaredButNotImplemented[0] != "POST /internal/v1/events" {
		t.Fatalf("DeclaredButNotImplemented = %v", diff.DeclaredButNotImplemented)
	}
	if !strings.Contains(diff.Err().Error(), "not implemented") {
		t.Fatalf("Err() = %v", diff.Err())
	}
}

// Direction 2: this service serves an operation the contract does not declare.
func TestCompareDetectsAnUndeclaredRoute(t *testing.T) {
	impl := append(fullImplementation(),
		contract.Operation{Method: "POST", Path: "/internal/v1/rerank", OperationID: "rerank", Statuses: []int{200}})
	diff := loadGood(t).Compare(impl)
	if len(diff.ImplementedButNotDeclared) != 1 || diff.ImplementedButNotDeclared[0] != "POST /internal/v1/rerank" {
		t.Fatalf("ImplementedButNotDeclared = %v", diff.ImplementedButNotDeclared)
	}
}

// Direction 2b: a renamed path is caught as both a missing and an undeclared
// route, which is the shape a typo actually takes.
func TestCompareDetectsARenamedPath(t *testing.T) {
	impl := fullImplementation()
	impl[2].Path = "/internal/v1/event"
	diff := loadGood(t).Compare(impl)
	if len(diff.DeclaredButNotImplemented) != 1 || len(diff.ImplementedButNotDeclared) != 1 {
		t.Fatalf("a renamed path produced %v / %v", diff.DeclaredButNotImplemented, diff.ImplementedButNotDeclared)
	}
}

func TestCompareDetectsAMethodChange(t *testing.T) {
	impl := fullImplementation()
	impl[1].Method = "GET"
	if loadGood(t).Compare(impl).Empty() {
		t.Fatal("Compare reported no drift when the verb changed")
	}
}

func TestCompareDetectsAnOperationIDChange(t *testing.T) {
	impl := fullImplementation()
	impl[1].OperationID = "searchInternalV2"
	diff := loadGood(t).Compare(impl)
	if len(diff.OperationIDMismatches) != 1 {
		t.Fatalf("OperationIDMismatches = %v", diff.OperationIDMismatches)
	}
}

// Direction 3: the route exists but answers with a status the contract never
// declared — the drift a handler edit actually produces.
func TestCompareDetectsAStatusMismatch(t *testing.T) {
	impl := fullImplementation()
	impl[1].Statuses = []int{200, 401, 503}
	diff := loadGood(t).Compare(impl)
	if len(diff.StatusMismatches) != 1 {
		t.Fatalf("StatusMismatches = %v", diff.StatusMismatches)
	}
	msg := diff.Err().Error()
	for _, want := range []string{"200,401", "200,401,503"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not show %q", msg, want)
		}
	}
}

func TestCompareDetectsADroppedStatus(t *testing.T) {
	impl := fullImplementation()
	impl[1].Statuses = []int{200}
	if len(loadGood(t).Compare(impl).StatusMismatches) != 1 {
		t.Fatal("dropping the 401 was not reported")
	}
}

// ------------------------------------------------------------- validation ---

func TestValidateAcceptsAConformingBody(t *testing.T) {
	doc := loadGood(t)
	for _, body := range []string{
		`{"status":"ok","total":3}`,
		`{"status":"not_indexed","total":0,"version":null}`,
		`{"status":"ok","total":1,"at":"2026-09-20T10:00:00Z","items":["a","b"]}`,
	} {
		if err := doc.Validate("Answer", []byte(body)); err != nil {
			t.Errorf("Validate rejected %s: %v", body, err)
		}
	}
}

func TestValidateRejectsDrift(t *testing.T) {
	doc := loadGood(t)
	cases := map[string]string{
		"an undeclared extra field":     `{"status":"ok","total":1,"reason":"x"}`,
		"a missing required field":      `{"status":"ok"}`,
		"an out-of-enum value":          `{"status":"empty","total":1}`,
		"a string where an int belongs": `{"status":"ok","total":"1"}`,
		"a null in a non-nullable":      `{"status":null,"total":1}`,
		"a bad date-time":               `{"status":"ok","total":1,"at":"yesterday"}`,
		"a scalar in an array":          `{"status":"ok","total":1,"items":"a"}`,
		"a non-string array element":    `{"status":"ok","total":1,"items":[1]}`,
		"an array at the top level":     `[]`,
		"trailing content":              `{"status":"ok","total":1} {}`,
		"not json":                      `nope`,
	}
	for name, body := range cases {
		if err := doc.Validate("Answer", []byte(body)); err == nil {
			t.Errorf("Validate accepted %s: %s", name, body)
		}
	}
}

func TestValidateAcceptsAnExplicitNullInANullableField(t *testing.T) {
	if err := loadGood(t).Validate("Answer", []byte(`{"status":"ok","total":0,"version":null}`)); err != nil {
		t.Fatalf("a null in a nullable field was rejected: %v", err)
	}
}

func TestValidateRefusesAnUndefinedSchema(t *testing.T) {
	if err := loadGood(t).Validate("Nope", []byte(`{}`)); err == nil {
		t.Fatal("Validate accepted an undefined schema name")
	}
}

func TestValidateRefusesAConstructItCannotCheck(t *testing.T) {
	// The validator must fail loudly rather than pass a schema it does not
	// understand, or the drift check would silently stop checking.
	doc, err := contract.Load("testdata/unsupported-composition.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = doc.Validate("Composed", []byte(`{"anything":1}`))
	if err == nil {
		t.Fatal("Validate silently accepted a oneOf schema it does not implement")
	}
	if !strings.Contains(err.Error(), "oneOf") {
		t.Fatalf("error %q does not name the unsupported construct", err.Error())
	}
}

func TestValidateResponseUsesTheDeclaredSchema(t *testing.T) {
	doc := loadGood(t)
	if err := doc.ValidateResponse("POST", "/internal/v1/search", 401, []byte(`{"code":"signature_rejected"}`)); err != nil {
		t.Fatalf("a conforming 401 was rejected: %v", err)
	}
	if err := doc.ValidateResponse("POST", "/internal/v1/search", 401, []byte(`{"status":"ok","total":0}`)); err == nil {
		t.Fatal("a 401 body shaped like a success answer was accepted")
	}
	if err := doc.ValidateResponse("POST", "/internal/v1/search", 418, []byte(`{}`)); err == nil {
		t.Fatal("ValidateResponse accepted a status the contract never declares")
	}
}

func TestDigestIsStable(t *testing.T) {
	// sha256("") — the well-known empty digest, so a broken hash is obvious.
	if got := contract.Digest(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("Digest(nil) = %s", got)
	}
	if contract.Digest([]byte("a")) == contract.Digest([]byte("b")) {
		t.Fatal("Digest collides on distinct inputs")
	}
}

// A $ref that points outside this document would make the drift check depend
// on a file nobody reviewed, and would turn the parser into a file-disclosure
// or SSRF primitive in whatever tool consumes the spec. Every non-local
// reference is refused before anything resolves one.
func TestParseRefusesANonLocalRef(t *testing.T) {
	cases := map[string]string{
		"a sibling file":   "common.yaml#/components/schemas/X",
		"an absolute path": "/etc/passwd",
		"a URL":            "https://example.invalid/openapi.yaml#/components/schemas/X",
		"a relative path":  "../vizra-core/api/openapi.yaml#/x",
		"a bare fragment":  "#components/schemas/X",
	}
	for name, ref := range cases {
		doc := "openapi: 3.0.3\n" +
			"paths:\n" +
			"  /internal/v1/search:\n" +
			"    post:\n" +
			"      operationId: x\n" +
			"      responses:\n" +
			"        \"200\":\n" +
			"          content:\n" +
			"            application/json:\n" +
			"              schema:\n" +
			"                $ref: \"" + ref + "\"\n"
		_, err := contract.Parse([]byte(doc))
		if err == nil {
			t.Errorf("Parse accepted %s: %s", name, ref)
			continue
		}
		if !strings.Contains(err.Error(), "local") {
			t.Errorf("%s: error %q does not explain the refusal", name, err.Error())
		}
	}
}

// The check reaches branches the rest of the parser never walks, such as a
// requestBody, so a hostile reference cannot hide where this parser does not
// look.
func TestParseRefusesANonLocalRefInAnUnwalkedBranch(t *testing.T) {
	doc := "openapi: 3.0.3\n" +
		"paths:\n" +
		"  /internal/v1/search:\n" +
		"    post:\n" +
		"      operationId: x\n" +
		"      requestBody:\n" +
		"        content:\n" +
		"          application/json:\n" +
		"            schema:\n" +
		"              $ref: \"https://example.invalid/evil.yaml#/x\"\n" +
		"      responses:\n" +
		"        \"200\": {description: ok}\n"
	if _, err := contract.Parse([]byte(doc)); err == nil {
		t.Fatal("a non-local $ref inside requestBody was accepted")
	}
}

func TestTheRealContractUsesOnlyLocalRefs(t *testing.T) {
	// The vendored canonical contract must itself satisfy the rule.
	if _, err := contract.Load("../../api/search-internal.openapi.yaml"); err != nil {
		t.Fatalf("the vendored canonical contract does not parse: %v", err)
	}
}
