// Package contract reads the canonical OpenAPI document owned by vizra-core
// and compares it against what this service actually serves.
//
// ADR-002 § "Search service and boundary (Q-001)" puts the internal contract in
// core's canonical OpenAPI and requires it to be drift-checked in both
// repositories. This package is the search side of that check. It fails in both
// directions — a route with no operation in the contract, and an operation in
// the contract with no route — and it validates response bodies against the
// contract's schemas, so a renamed or added response field turns CI red too.
//
// Scope of the validator. It covers the subset of JSON Schema this contract
// uses: $ref, type, enum, required, properties, additionalProperties, items,
// nullable and the date-time format. It does not implement oneOf, allOf, anyOf,
// patternProperties or numeric bounds, and it refuses a document that uses a
// construct it does not understand rather than passing it silently.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// InternalPrefix is the prefix of the HMAC-authenticated operations.
const InternalPrefix = "/internal/v1/"

// ErrContract wraps every failure this package produces.
var ErrContract = errors.New("contract")

// Operation is one method/path pair with its declared responses.
type Operation struct {
	Method      string
	Path        string
	OperationID string
	// Statuses are the declared response status codes, sorted.
	Statuses []int
	// ResponseSchema maps a status code to the name of the schema its JSON body
	// must satisfy. A status with no JSON body is absent.
	ResponseSchema map[int]string
	// Secured is true when the operation declares a non-empty security
	// requirement.
	Secured bool
}

// Key is the stable identity of an operation.
func (o Operation) Key() string { return o.Method + " " + o.Path }

func (o Operation) statusList() string {
	parts := make([]string, 0, len(o.Statuses))
	for _, s := range o.Statuses {
		parts = append(parts, strconv.Itoa(s))
	}
	return strings.Join(parts, ",")
}

// Doc is the parsed subset of an OpenAPI document.
type Doc struct {
	OpenAPI    string
	Title      string
	Version    string
	Operations []Operation

	schemas map[string]any
	raw     map[string]any
}

var httpMethods = map[string]string{
	"get": "GET", "put": "PUT", "post": "POST", "delete": "DELETE",
	"options": "OPTIONS", "head": "HEAD", "patch": "PATCH", "trace": "TRACE",
}

// Parse reads an OpenAPI document.
func Parse(data []byte) (*Doc, error) {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%w: cannot parse the OpenAPI document: %w", ErrContract, err)
	}
	if root == nil {
		return nil, fmt.Errorf("%w: the document is empty", ErrContract)
	}
	openapi, _ := root["openapi"].(string)
	if strings.TrimSpace(openapi) == "" {
		return nil, fmt.Errorf("%w: the document has no top-level \"openapi\" version field", ErrContract)
	}

	// Every $ref must be local before anything resolves one. A $ref to
	// another file or a URL would make the drift check depend on a document
	// nobody reviewed, and would turn the parser into an SSRF or
	// file-disclosure primitive in whatever tool consumes it. The check runs
	// over the whole tree, including branches this parser never walks.
	if err := rejectNonLocalRefs(root, "$"); err != nil {
		return nil, err
	}

	doc := &Doc{OpenAPI: openapi, raw: root, schemas: map[string]any{}}
	if info, ok := root["info"].(map[string]any); ok {
		doc.Title, _ = info["title"].(string)
		doc.Version, _ = info["version"].(string)
	}
	if components, ok := root["components"].(map[string]any); ok {
		if schemas, ok := components["schemas"].(map[string]any); ok {
			doc.schemas = schemas
		}
	}

	paths, ok := root["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, fmt.Errorf("%w: the document declares no paths", ErrContract)
	}

	for path, rawItem := range paths {
		item, ok := rawItem.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: path %q is not an object", ErrContract, path)
		}
		for key, rawOp := range item {
			method, ok := httpMethods[strings.ToLower(key)]
			if !ok {
				continue
			}
			op, ok := rawOp.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: operation %s %s is not an object", ErrContract, method, path)
			}
			parsed, err := doc.parseOperation(method, path, op)
			if err != nil {
				return nil, err
			}
			doc.Operations = append(doc.Operations, parsed)
		}
	}
	if len(doc.Operations) == 0 {
		return nil, fmt.Errorf("%w: the document declares no operations", ErrContract)
	}
	if !doc.hasInternalOperation() {
		return nil, fmt.Errorf("%w: the document declares no operations under %s; this is not the core↔search contract", ErrContract, InternalPrefix)
	}
	sort.Slice(doc.Operations, func(i, j int) bool { return doc.Operations[i].Key() < doc.Operations[j].Key() })
	return doc, nil
}

// rejectNonLocalRefs walks the document and fails on any $ref that is not a
// local JSON pointer into this same document.
func rejectNonLocalRefs(node any, path string) error {
	switch v := node.(type) {
	case map[string]any:
		for key, value := range v {
			if key == "$ref" {
				ref, ok := value.(string)
				if !ok {
					return fmt.Errorf("%w: %s.$ref is not a string", ErrContract, path)
				}
				if !strings.HasPrefix(ref, "#/") {
					return fmt.Errorf("%w: %s.$ref = %q is not a local reference; only local \"#/...\" references are allowed, so the contract cannot pull in a document nobody reviewed", ErrContract, path, ref)
				}
				continue
			}
			if err := rejectNonLocalRefs(value, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := rejectNonLocalRefs(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Doc) hasInternalOperation() bool {
	for _, op := range d.Operations {
		if strings.HasPrefix(op.Path, InternalPrefix) {
			return true
		}
	}
	return false
}

func (d *Doc) parseOperation(method, path string, op map[string]any) (Operation, error) {
	out := Operation{Method: method, Path: path, ResponseSchema: map[int]string{}}
	out.OperationID, _ = op["operationId"].(string)
	if out.OperationID == "" {
		return out, fmt.Errorf("%w: operation %s %s has no operationId", ErrContract, method, path)
	}

	if security, present := op["security"]; present {
		list, ok := security.([]any)
		if !ok {
			return out, fmt.Errorf("%w: operation %s %s has a malformed security list", ErrContract, method, path)
		}
		out.Secured = len(list) > 0
	}

	responses, ok := op["responses"].(map[string]any)
	if !ok || len(responses) == 0 {
		return out, fmt.Errorf("%w: operation %s %s declares no responses", ErrContract, method, path)
	}
	for code, rawResp := range responses {
		status, err := strconv.Atoi(code)
		if err != nil {
			return out, fmt.Errorf("%w: operation %s %s declares a non-numeric response code %q; the drift check requires exact status codes", ErrContract, method, path, code)
		}
		out.Statuses = append(out.Statuses, status)

		resp, err := d.resolveNode(rawResp)
		if err != nil {
			return out, fmt.Errorf("%w: operation %s %s response %d: %w", ErrContract, method, path, status, err)
		}
		name, err := d.jsonSchemaName(resp)
		if err != nil {
			return out, fmt.Errorf("%w: operation %s %s response %d: %w", ErrContract, method, path, status, err)
		}
		if name != "" {
			out.ResponseSchema[status] = name
		}
	}
	sort.Ints(out.Statuses)
	return out, nil
}

// jsonSchemaName returns the components/schemas name of a response's
// application/json body, or "" when the response has no JSON body.
func (d *Doc) jsonSchemaName(resp any) (string, error) {
	respMap, ok := resp.(map[string]any)
	if !ok {
		return "", errors.New("the response is not an object")
	}
	content, ok := respMap["content"].(map[string]any)
	if !ok {
		return "", nil
	}
	media, ok := content["application/json"].(map[string]any)
	if !ok {
		return "", nil
	}
	schema, ok := media["schema"].(map[string]any)
	if !ok {
		return "", errors.New("the application/json media type declares no schema")
	}
	ref, ok := schema["$ref"].(string)
	if !ok {
		return "", errors.New("the response schema must be a $ref to components/schemas, so both repositories name the same shape")
	}
	name := strings.TrimPrefix(ref, "#/components/schemas/")
	if name == ref {
		return "", fmt.Errorf("unsupported schema reference %q", ref)
	}
	if _, ok := d.schemas[name]; !ok {
		return "", fmt.Errorf("the document references an undefined schema %q", name)
	}
	return name, nil
}

// resolveNode follows a $ref into components/responses or components/schemas.
func (d *Doc) resolveNode(node any) (any, error) {
	m, ok := node.(map[string]any)
	if !ok {
		return node, nil
	}
	ref, ok := m["$ref"].(string)
	if !ok {
		return node, nil
	}
	const (
		responsePrefix = "#/components/responses/"
		schemaPrefix   = "#/components/schemas/"
	)
	components, _ := d.raw["components"].(map[string]any)
	switch {
	case strings.HasPrefix(ref, responsePrefix):
		table, _ := components["responses"].(map[string]any)
		target, ok := table[strings.TrimPrefix(ref, responsePrefix)]
		if !ok {
			return nil, fmt.Errorf("undefined response reference %q", ref)
		}
		return target, nil
	case strings.HasPrefix(ref, schemaPrefix):
		target, ok := d.schemas[strings.TrimPrefix(ref, schemaPrefix)]
		if !ok {
			return nil, fmt.Errorf("undefined schema reference %q", ref)
		}
		return target, nil
	default:
		return nil, fmt.Errorf("unsupported reference %q", ref)
	}
}

// Load reads and parses a document from disk.
func Load(path string) (*Doc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %w", ErrContract, path, err)
	}
	return Parse(data)
}

// Digest returns the lowercase hex sha256 of the given bytes. It proves a
// vendored copy of the canonical contract has not been edited in place.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ------------------------------------------------------------ comparison ---

// Diff is the result of comparing a contract with an implementation.
type Diff struct {
	DeclaredButNotImplemented []string
	ImplementedButNotDeclared []string
	StatusMismatches          []string
	OperationIDMismatches     []string
}

// Empty reports whether the implementation matches the contract exactly.
func (d Diff) Empty() bool {
	return len(d.DeclaredButNotImplemented) == 0 &&
		len(d.ImplementedButNotDeclared) == 0 &&
		len(d.StatusMismatches) == 0 &&
		len(d.OperationIDMismatches) == 0
}

// Err returns a single error describing every difference, or nil.
func (d Diff) Err() error {
	if d.Empty() {
		return nil
	}
	var b strings.Builder
	b.WriteString("the implementation has drifted from the canonical contract:")
	for _, s := range d.DeclaredButNotImplemented {
		b.WriteString("\n  - declared in the contract but not implemented: " + s)
	}
	for _, s := range d.ImplementedButNotDeclared {
		b.WriteString("\n  - implemented but not declared in the contract: " + s)
	}
	for _, s := range d.StatusMismatches {
		b.WriteString("\n  - response status codes differ: " + s)
	}
	for _, s := range d.OperationIDMismatches {
		b.WriteString("\n  - operationId differs: " + s)
	}
	return fmt.Errorf("%w: %s", ErrContract, b.String())
}

// Compare checks implemented operations against the document, in both
// directions. An implemented operation's Statuses must equal the contract's
// declared set exactly — callers that do not yet emit a declared status
// account for it explicitly rather than by omission.
func (d *Doc) Compare(implemented []Operation) Diff {
	declared := make(map[string]Operation, len(d.Operations))
	for _, op := range d.Operations {
		declared[op.Key()] = op
	}
	impl := make(map[string]Operation, len(implemented))
	for _, op := range implemented {
		impl[op.Key()] = op
	}

	var diff Diff
	for key, op := range declared {
		other, ok := impl[key]
		if !ok {
			diff.DeclaredButNotImplemented = append(diff.DeclaredButNotImplemented, key)
			continue
		}
		if !sameInts(op.Statuses, other.Statuses) {
			diff.StatusMismatches = append(diff.StatusMismatches,
				fmt.Sprintf("%s (contract: %s; implementation: %s)", key, op.statusList(), other.statusList()))
		}
		if other.OperationID != "" && other.OperationID != op.OperationID {
			diff.OperationIDMismatches = append(diff.OperationIDMismatches,
				fmt.Sprintf("%s (contract: %s; implementation: %s)", key, op.OperationID, other.OperationID))
		}
	}
	for key := range impl {
		if _, ok := declared[key]; !ok {
			diff.ImplementedButNotDeclared = append(diff.ImplementedButNotDeclared, key)
		}
	}

	sort.Strings(diff.DeclaredButNotImplemented)
	sort.Strings(diff.ImplementedButNotDeclared)
	sort.Strings(diff.StatusMismatches)
	sort.Strings(diff.OperationIDMismatches)
	return diff
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]int(nil), a...)
	y := append([]int(nil), b...)
	sort.Ints(x)
	sort.Ints(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------- validation ---

// ResponseSchemaFor returns the schema name a response body must satisfy.
func (d *Doc) ResponseSchemaFor(method, path string, status int) (string, bool) {
	for _, op := range d.Operations {
		if op.Method == method && op.Path == path {
			name, ok := op.ResponseSchema[status]
			return name, ok
		}
	}
	return "", false
}

// ValidateResponse checks a JSON response body against the schema the contract
// declares for that operation and status.
func (d *Doc) ValidateResponse(method, path string, status int, body []byte) error {
	name, ok := d.ResponseSchemaFor(method, path, status)
	if !ok {
		return fmt.Errorf("%w: the contract declares no application/json body for %s %s %d", ErrContract, method, path, status)
	}
	if err := d.Validate(name, body); err != nil {
		return fmt.Errorf("%s %s %d: %w", method, path, status, err)
	}
	return nil
}

// Validate checks a JSON document against a named schema.
func (d *Doc) Validate(schemaName string, body []byte) error {
	schema, ok := d.schemas[schemaName]
	if !ok {
		return fmt.Errorf("%w: undefined schema %q", ErrContract, schemaName)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("%w: the body is not JSON: %w", ErrContract, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: the body carries trailing content after the JSON document", ErrContract)
	}
	return d.validate(schemaName, schema, value)
}

func (d *Doc) validate(path string, rawSchema, value any) error {
	resolved, err := d.resolveNode(rawSchema)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrContract, path, err)
	}
	schema, ok := resolved.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: %s: the schema is not an object", ErrContract, path)
	}

	for _, unsupported := range []string{"oneOf", "allOf", "anyOf", "not", "patternProperties"} {
		if _, present := schema[unsupported]; present {
			return fmt.Errorf("%w: %s: the contract uses %q, which this validator does not implement; extend the validator rather than skipping the check", ErrContract, path, unsupported)
		}
	}

	nullable, _ := schema["nullable"].(bool)
	if value == nil {
		if nullable {
			return nil
		}
		return fmt.Errorf("%w: %s: null is not allowed", ErrContract, path)
	}

	if enum, present := schema["enum"].([]any); present {
		if !enumContains(enum, value) {
			return fmt.Errorf("%w: %s: %v is not one of the declared values %v", ErrContract, path, value, enum)
		}
	}

	typ, _ := schema["type"].(string)
	switch typ {
	case "object":
		return d.validateObject(path, schema, value)
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%w: %s: expected an array", ErrContract, path)
		}
		itemSchema, present := schema["items"]
		if !present {
			return fmt.Errorf("%w: %s: the array schema declares no items", ErrContract, path)
		}
		for i, item := range items {
			if err := d.validate(fmt.Sprintf("%s[%d]", path, i), itemSchema, item); err != nil {
				return err
			}
		}
		return nil
	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%w: %s: expected a string, got %T", ErrContract, path, value)
		}
		if format, _ := schema["format"].(string); format == "date-time" {
			if _, err := time.Parse(time.RFC3339, s); err != nil {
				return fmt.Errorf("%w: %s: %q is not an RFC 3339 date-time", ErrContract, path, s)
			}
		}
		return nil
	case "integer":
		n, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("%w: %s: expected an integer, got %T", ErrContract, path, value)
		}
		if _, err := n.Int64(); err != nil {
			return fmt.Errorf("%w: %s: %s is not an integer", ErrContract, path, n)
		}
		return nil
	case "number":
		if _, ok := value.(json.Number); !ok {
			return fmt.Errorf("%w: %s: expected a number, got %T", ErrContract, path, value)
		}
		return nil
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%w: %s: expected a boolean, got %T", ErrContract, path, value)
		}
		return nil
	case "":
		// An untyped schema constrains nothing beyond what was checked above.
		return nil
	default:
		return fmt.Errorf("%w: %s: unsupported schema type %q", ErrContract, path, typ)
	}
}

func (d *Doc) validateObject(path string, schema map[string]any, value any) error {
	obj, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: %s: expected an object, got %T", ErrContract, path, value)
	}

	properties, _ := schema["properties"].(map[string]any)

	if required, ok := schema["required"].([]any); ok {
		for _, r := range required {
			name, _ := r.(string)
			if _, present := obj[name]; !present {
				return fmt.Errorf("%w: %s: the required property %q is missing", ErrContract, path, name)
			}
		}
	}

	// additionalProperties: false is the whole point of the check — a renamed
	// or invented response field must be a failure, not a tolerated extra.
	if extra, present := schema["additionalProperties"]; present {
		if allowed, ok := extra.(bool); ok && !allowed {
			var unknown []string
			for name := range obj {
				if _, declared := properties[name]; !declared {
					unknown = append(unknown, name)
				}
			}
			if len(unknown) > 0 {
				sort.Strings(unknown)
				return fmt.Errorf("%w: %s: the contract forbids additional properties, but the body carries %s", ErrContract, path, strings.Join(unknown, ", "))
			}
		}
	}

	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		propSchema, declared := properties[name]
		if !declared {
			continue
		}
		if err := d.validate(path+"."+name, propSchema, obj[name]); err != nil {
			return err
		}
	}
	return nil
}

func enumContains(enum []any, value any) bool {
	for _, candidate := range enum {
		if fmt.Sprint(candidate) == fmt.Sprint(value) {
			return true
		}
	}
	return false
}
