// Package httpapi is the only package in this repository that imports Echo.
//
// ADR-001 confines Echo types to one package so the major version is
// replaceable in one place; `make echo-containment` enforces that.
//
// Every operation served here is declared in Routes(), and the contract drift
// check compares Routes() against the canonical OpenAPI document vizra-core
// owns (vendored at api/search-internal.openapi.yaml). Response bodies are
// validated against that document's schemas in the same check, so a renamed
// field fails CI as loudly as a renamed route.
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/yegamble/vizra-search/internal/buildinfo"
	"github.com/yegamble/vizra-search/internal/config"
	"github.com/yegamble/vizra-search/internal/contract"
	"github.com/yegamble/vizra-search/internal/hmacauth"
)

// Index statuses of the contract's IndexStatus enum.
const (
	// StatusNotIndexed is the explicit status Q-001 requires. It is a
	// successful answer meaning "I hold no index; use your own SQL path", and
	// it is never used to report a fault.
	StatusNotIndexed = "not_indexed"
	StatusOK         = "ok"
)

// Error codes of the contract's Error.code enum.
const (
	codeBadRequest        = "bad_request"
	codeSignatureRejected = "signature_rejected"
	codePayloadTooLarge   = "payload_too_large"
	codeInternalError     = "internal_error"
	codeUnavailable       = "unavailable"
)

// Route describes one served operation.
type Route struct {
	Method      string
	Path        string
	OperationID string
	// Emitted are the status codes this service can actually produce, each
	// proven reachable by TestEveryEmittedStatusIsReachable.
	Emitted []int
	// DeclaredNotEmitted are status codes the contract declares that this
	// service cannot currently produce, each with a written reason. The drift
	// check requires Emitted ∪ DeclaredNotEmitted to equal the contract's
	// declared set exactly, so a status added in core turns this repository red
	// until someone classifies it here.
	DeclaredNotEmitted map[int]string
}

// Statuses is the full declared set for the drift comparison.
func (r Route) Statuses() []int {
	out := append([]int(nil), r.Emitted...)
	for status := range r.DeclaredNotEmitted {
		out = append(out, status)
	}
	return out
}

const (
	pathHealthz     = "/healthz"
	pathReadyz      = "/readyz"
	pathVersion     = "/version"
	pathSearch      = "/internal/v1/search"
	pathSuggestions = "/internal/v1/suggestions"
	pathEvents      = "/internal/v1/events"
)

// reasonNo500 explains why this service cannot currently emit a 500.
const reasonNo500 = "vizra-search has no dependency that can fault at M0: it holds no database, no cache and no index. " +
	"The 500 path exists in the error handler and is covered by TestErrorHandlerRendersTheContractErrorShape, " +
	"but no request can provoke it, so claiming it as reachable would be false."

// routes is the complete surface. The order is the contract's.
var routes = []Route{
	{
		Method: http.MethodGet, Path: pathHealthz, OperationID: "searchGetHealthz",
		Emitted: []int{http.StatusOK},
		DeclaredNotEmitted: map[int]string{
			// ADR-002 § Probes: "/healthz is liveness only". A draining process
			// is still alive, and an orchestrator must stop routing to it via
			// /readyz rather than restarting it via /healthz.
			http.StatusServiceUnavailable: "liveness stays 200 while draining (ADR-002 § Probes); readiness is what goes 503",
		},
	},
	{
		Method: http.MethodGet, Path: pathReadyz, OperationID: "searchGetReadyz",
		Emitted:            []int{http.StatusOK, http.StatusServiceUnavailable},
		DeclaredNotEmitted: map[int]string{},
	},
	{
		Method: http.MethodGet, Path: pathVersion, OperationID: "searchGetVersion",
		Emitted:            []int{http.StatusOK},
		DeclaredNotEmitted: map[int]string{},
	},
	{
		Method: http.MethodPost, Path: pathSearch, OperationID: "internalSearch",
		Emitted: []int{
			http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized,
			http.StatusRequestEntityTooLarge, http.StatusServiceUnavailable,
		},
		DeclaredNotEmitted: map[int]string{http.StatusInternalServerError: reasonNo500},
	},
	{
		Method: http.MethodPost, Path: pathSuggestions, OperationID: "internalSuggestions",
		Emitted: []int{
			http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized,
			http.StatusRequestEntityTooLarge, http.StatusServiceUnavailable,
		},
		DeclaredNotEmitted: map[int]string{http.StatusInternalServerError: reasonNo500},
	},
	{
		Method: http.MethodPost, Path: pathEvents, OperationID: "internalEvents",
		Emitted: []int{
			http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized,
			http.StatusRequestEntityTooLarge, http.StatusServiceUnavailable,
		},
		DeclaredNotEmitted: map[int]string{http.StatusInternalServerError: reasonNo500},
	},
}

// Routes returns the served surface as contract operations.
func Routes() []contract.Operation {
	ops := make([]contract.Operation, 0, len(routes))
	for _, r := range routes {
		ops = append(ops, contract.Operation{
			Method:      r.Method,
			Path:        r.Path,
			OperationID: r.OperationID,
			Statuses:    r.Statuses(),
		})
	}
	return ops
}

// RouteTable exposes the routes with their emitted/not-emitted classification,
// for the tests that prove the classification honest.
func RouteTable() []Route { return append([]Route(nil), routes...) }

// NewLogger builds the service logger. It emits JSON and, by construction,
// never receives headers or bodies (ADR-002 § Logging and redaction).
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Server is the HTTP surface of vizra-search.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	verifier *hmacauth.Verifier
	echo     *echo.Echo

	draining atomic.Bool

	// lastDeadline records the deadline the most recent internal handler saw,
	// so a test can prove deadlines are propagated rather than declared.
	lastDeadline atomic.Int64

	// now is injectable so a test can pin checked_at.
	now func() time.Time
}

// New builds the server. A nil configuration is a programming error and panics
// at boot rather than serving unauthenticated traffic.
func New(cfg *config.Config, log *slog.Logger) *Server {
	if cfg == nil {
		panic("httpapi.New: nil configuration")
	}
	if log == nil {
		log = NewLogger(io.Discard)
	}

	s := &Server{
		cfg: cfg,
		log: log,
		now: time.Now,
		verifier: &hmacauth.Verifier{
			Key:     cfg.HMACKey,
			MaxSkew: cfg.MaxClockSkew,
		},
	}

	e := echo.New()
	e.HTTPErrorHandler = s.errorHandler

	probes := map[string]echo.HandlerFunc{
		pathHealthz: s.handleHealthz,
		pathReadyz:  s.handleReadyz,
		pathVersion: s.handleVersion,
	}
	internal := map[string]func(*echo.Context, []byte) error{
		pathSearch:      s.handleSearch,
		pathSuggestions: s.handleSuggestions,
		pathEvents:      s.handleEvents,
	}

	for _, r := range routes {
		switch {
		case probes[r.Path] != nil:
			e.Add(r.Method, r.Path, probes[r.Path])
		case internal[r.Path] != nil:
			e.Add(r.Method, r.Path, s.authenticated(internal[r.Path]))
		default:
			panic("httpapi.New: no handler for declared route " + r.Path)
		}
	}

	s.echo = e
	return s
}

// Handler exposes the router as a standard http.Handler, so nothing outside
// this package has to know about Echo.
func (s *Server) Handler() http.Handler { return s.echo }

// BeginDrain flips readiness to draining. Liveness stays healthy.
func (s *Server) BeginDrain() { s.draining.Store(true) }

// Draining reports whether the server has begun draining.
func (s *Server) Draining() bool { return s.draining.Load() }

// LastRequestDeadline returns the deadline the most recent internal handler
// observed on its request context.
func (s *Server) LastRequestDeadline() (time.Time, bool) {
	nanos := s.lastDeadline.Load()
	if nanos == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, nanos), true
}

// ------------------------------------------------------------- middleware ---

// authenticated wraps an internal handler with the body bound, HMAC
// verification and a request deadline, in that order.
func (s *Server) authenticated(h func(*echo.Context, []byte) error) echo.HandlerFunc {
	return func(c *echo.Context) error {
		req := c.Request()

		// 1. Bound the request before reading it, as the contract requires:
		//    "reject a body above MAX_INTERNAL_BODY_BYTES *before* reading it,
		//    with 413". A declared Content-Length above the limit is refused
		//    without reading a byte; a chunked body is bounded by the reader.
		if declared := req.ContentLength; declared > s.cfg.MaxBodyBytes {
			return s.refuseTooLarge(c, declared)
		}
		body, tooLarge, err := readBounded(req.Body, s.cfg.MaxBodyBytes)
		if err != nil {
			return writeError(c, http.StatusBadRequest, codeBadRequest, "the request body could not be read")
		}
		if tooLarge {
			return s.refuseTooLarge(c, -1)
		}

		// 2. Authenticate over the exact bytes received. The response never
		//    says which header was wrong — the contract forbids it.
		if err := s.verifier.Verify(req.Method, c.Path(), req.Header, body); err != nil {
			var authErr *hmacauth.Error
			reason := string(hmacauth.ReasonBadSignature)
			if errors.As(err, &authErr) {
				reason = string(authErr.Reason)
			}
			// The specific reason is logged for the operator and withheld from
			// the caller.
			s.log.Warn("request refused",
				slog.String("method", req.Method),
				slog.String("path", c.Path()),
				slog.Int("status", http.StatusUnauthorized),
				slog.String("reason", reason),
			)
			return writeError(c, http.StatusUnauthorized, codeSignatureRejected, "request authentication failed")
		}

		// 3. A draining process is a fault from core's point of view, not an
		//    empty index: core must fall back to SQL and report degraded,
		//    which is exactly what a 5xx means in this contract.
		if s.draining.Load() {
			return writeError(c, http.StatusServiceUnavailable, codeUnavailable, "the service is draining")
		}

		// 4. Bound the handler's own time and propagate cancellation.
		ctx, cancel := contextWithTimeout(req.Context(), s.cfg.RequestTimeout)
		defer cancel()
		if deadline, ok := ctx.Deadline(); ok {
			s.lastDeadline.Store(deadline.UnixNano())
		}
		c.SetRequest(req.WithContext(ctx))

		s.log.Info("request",
			slog.String("method", req.Method),
			slog.String("path", c.Path()),
			slog.Int64("body_bytes", int64(len(body))),
		)
		return h(c, body)
	}
}

func (s *Server) refuseTooLarge(c *echo.Context, declared int64) error {
	attrs := []any{
		slog.String("method", c.Request().Method),
		slog.String("path", c.Path()),
		slog.Int("status", http.StatusRequestEntityTooLarge),
		slog.Int64("limit_bytes", s.cfg.MaxBodyBytes),
	}
	if declared >= 0 {
		attrs = append(attrs, slog.Int64("declared_bytes", declared))
	}
	s.log.Warn("request refused", attrs...)
	return writeError(c, http.StatusRequestEntityTooLarge, codePayloadTooLarge,
		"the request body exceeds "+config.EnvMaxBodyBytes+" ("+strconv.FormatInt(s.cfg.MaxBodyBytes, 10)+" bytes)")
}

// readBounded reads at most limit bytes and reports whether more were
// available. It never allocates more than limit+1 bytes.
func readBounded(r io.Reader, limit int64) (body []byte, tooLarge bool, err error) {
	if r == nil {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, true, nil
	}
	return data, false, nil
}

// ---------------------------------------------------------------- probes ---

// healthResponse is the contract's HealthResponse.
type healthResponse struct {
	Status string `json:"status"`
}

func (s *Server) handleHealthz(c *echo.Context) error {
	// Liveness only: 200 as long as the process is running, including while
	// draining (ADR-002 § Probes).
	return c.JSON(http.StatusOK, healthResponse{Status: "ok"})
}

// readinessComponent is the contract's SearchReadinessComponent. The contract
// restricts `name` to the enum [database]; this service has no database at M0,
// so the array is legitimately empty.
type readinessComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// readinessResponse is the contract's SearchReadinessResponse.
type readinessResponse struct {
	Status              string               `json:"status"`
	Components          []readinessComponent `json:"components"`
	SearchSchemaVersion *int64               `json:"search_schema_version"`
	CheckedAt           string               `json:"checked_at"`
}

func (s *Server) handleReadyz(c *echo.Context) error {
	body := readinessResponse{
		Status: "ok",
		// No component has a dependency to report at M0: this service holds no
		// database. An empty array is the honest answer, not a fabricated
		// healthy component.
		Components: []readinessComponent{},
		// Q-001: null until vizra-search owns migrations. Null is the correct
		// M0 value and is not a fault.
		SearchSchemaVersion: buildinfo.SearchSchemaVersion(),
		CheckedAt:           s.now().UTC().Format(time.RFC3339),
	}
	if s.draining.Load() {
		body.Status = "unavailable"
		return c.JSON(http.StatusServiceUnavailable, body)
	}
	return c.JSON(http.StatusOK, body)
}

// versionResponse is the contract's SearchVersionResponse.
type versionResponse struct {
	Release             string  `json:"release"`
	Commit              string  `json:"commit"`
	BuiltAt             string  `json:"built_at"`
	GoVersion           string  `json:"go_version"`
	ImageDigest         *string `json:"image_digest"`
	SearchSchemaVersion *int64  `json:"search_schema_version"`
}

func (s *Server) handleVersion(c *echo.Context) error {
	return c.JSON(http.StatusOK, versionResponse{
		Release:     buildinfo.Version,
		Commit:      buildinfo.Commit,
		BuiltAt:     buildinfo.BuildTime,
		GoVersion:   buildinfo.GoVersion(),
		ImageDigest: buildinfo.ImageDigest(),
		// Q-001: no migrations yet, so this is explicitly null — present so
		// core can distinguish "no schema" from "field missing".
		SearchSchemaVersion: buildinfo.SearchSchemaVersion(),
	})
}

// ------------------------------------------------------ internal handlers ---

// searchResponse is the contract's SearchResponse.
type searchResponse struct {
	Status              string     `json:"status"`
	Results             []struct{} `json:"results"`
	Total               int64      `json:"total"`
	SearchSchemaVersion *int64     `json:"search_schema_version"`
}

// suggestResponse is the contract's SuggestResponse. It carries no
// search_schema_version: the contract's SuggestResponse does not declare one
// and forbids additional properties.
type suggestResponse struct {
	Status      string     `json:"status"`
	Suggestions []struct{} `json:"suggestions"`
}

// eventAck is the contract's EventAck.
type eventAck struct {
	Status     string `json:"status"`
	Accepted   int    `json:"accepted"`
	Duplicates int    `json:"duplicates"`
}

// viewerContext and siteContext mirror the required parts of the request
// schemas. They exist so a request that omits them is a real 400 rather than a
// silently accepted malformed call.
type viewerContext struct {
	IsAnonymous *bool   `json:"is_anonymous"`
	Role        *string `json:"role"`
}

type siteContext struct {
	Handle *string `json:"handle"`
}

type searchRequest struct {
	Query  *string        `json:"query"`
	Viewer *viewerContext `json:"viewer"`
	Site   *siteContext   `json:"site"`
}

type suggestRequest struct {
	Prefix *string        `json:"prefix"`
	Viewer *viewerContext `json:"viewer"`
	Site   *siteContext   `json:"site"`
}

type eventBatch struct {
	Site   *siteContext      `json:"site"`
	Events []json.RawMessage `json:"events"`
}

// decodeStrict rejects trailing content. Unknown fields are tolerated on the
// request side so core can add an optional field without breaking this service
// before it is redeployed; the response side is strict, which is where drift
// would actually mislead a caller.
func decodeStrict(body []byte, into any) error {
	if len(body) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "a request body is required")
	}
	dec := json.NewDecoder(newByteReader(body))
	if err := dec.Decode(into); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "the request body is not a JSON object matching the contract")
	}
	if dec.More() {
		return echo.NewHTTPError(http.StatusBadRequest, "the request body carries trailing content")
	}
	return nil
}

func requireViewerAndSite(viewer *viewerContext, site *siteContext) error {
	if viewer == nil || viewer.IsAnonymous == nil || viewer.Role == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "viewer is required, with is_anonymous and role")
	}
	if site == nil || site.Handle == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "site is required, with handle")
	}
	return nil
}

func (s *Server) handleSearch(c *echo.Context, body []byte) error {
	var req searchRequest
	if err := decodeStrict(body, &req); err != nil {
		return err
	}
	if req.Query == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "query is required")
	}
	if err := requireViewerAndSite(req.Viewer, req.Site); err != nil {
		return err
	}
	// No index exists, so there is nothing to project and nothing to leak. The
	// viewer context is still required, so core cannot start omitting it and
	// discover the omission only in M3.
	return c.JSON(http.StatusOK, searchResponse{
		Status:              StatusNotIndexed,
		Results:             []struct{}{},
		Total:               0,
		SearchSchemaVersion: buildinfo.SearchSchemaVersion(),
	})
}

func (s *Server) handleSuggestions(c *echo.Context, body []byte) error {
	var req suggestRequest
	if err := decodeStrict(body, &req); err != nil {
		return err
	}
	if req.Prefix == nil || *req.Prefix == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "prefix is required and must not be empty")
	}
	if err := requireViewerAndSite(req.Viewer, req.Site); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, suggestResponse{
		Status:      StatusNotIndexed,
		Suggestions: []struct{}{},
	})
}

func (s *Server) handleEvents(c *echo.Context, body []byte) error {
	var batch eventBatch
	if err := decodeStrict(body, &batch); err != nil {
		return err
	}
	if batch.Site == nil || batch.Site.Handle == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "site is required, with handle")
	}
	if len(batch.Events) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "events must carry at least one event")
	}
	if len(batch.Events) > 500 {
		return echo.NewHTTPError(http.StatusBadRequest, "events must carry at most 500 events")
	}
	// not_indexed with accepted:0 tells core the events were deliberately
	// discarded because no index exists, so core marks the job succeeded
	// instead of retrying forever. Reporting a non-zero accepted count here
	// would be a lie that hides a lost event.
	return c.JSON(http.StatusOK, eventAck{
		Status:     StatusNotIndexed,
		Accepted:   0,
		Duplicates: 0,
	})
}

// ------------------------------------------------------------------ errors ---

// errorBody is the contract's Error.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(c *echo.Context, status int, code, message string) error {
	return c.JSON(status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// errorHandler renders every framework error in the contract's Error shape, so
// no caller ever gets an HTML body or an undeclared field from this service.
func (s *Server) errorHandler(c *echo.Context, err error) {
	resp, status := echo.ResolveResponseStatus(c.Response(), err)
	if resp != nil && resp.Committed {
		return
	}
	message := http.StatusText(status)
	var he *echo.HTTPError
	if errors.As(err, &he) {
		message = he.Message
	}
	if status >= http.StatusInternalServerError {
		// The error text may carry internals, so it is logged, not returned.
		s.log.Error("unhandled error", slog.String("path", c.Path()), slog.Int("status", status))
		message = "internal error"
	}
	_ = writeError(c, status, codeFor(status), message)
}

func codeFor(status int) string {
	switch status {
	case http.StatusBadRequest:
		return codeBadRequest
	case http.StatusUnauthorized:
		return codeSignatureRejected
	case http.StatusRequestEntityTooLarge:
		return codePayloadTooLarge
	case http.StatusServiceUnavailable:
		return codeUnavailable
	default:
		// 404 and 405 are not in the contract's Error.code enum, because the
		// contract declares no 404 or 405 response. They are router-level
		// answers to a request the contract never describes, so they carry the
		// generic fault code rather than inventing an undeclared one.
		return codeInternalError
	}
}
