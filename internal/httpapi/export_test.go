package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/yegamble/vizra-search/internal/config"
)

// RenderErrorForTest drives the production error handler directly. It exists
// because vizra-search has no dependency that can fault at M0, so no request
// can provoke a 500 — but the renderer for it must still be proven to produce
// the contract's Error shape. It is only compiled into the test binary.
func (s *Server) RenderErrorForTest(w http.ResponseWriter, r *http.Request, err error) {
	c := s.echo.AcquireContext()
	defer s.echo.ReleaseContext(c)
	c.Reset(r, echo.NewResponse(w, s.log))
	s.errorHandler(c, err)
}

// NewWithProbeRouteForTest builds a server with one extra, PARAMETERISED route
// registered at /probe/:id. No production route carries a path parameter today,
// which is exactly why the property needs a test: Echo's c.Path() returns the
// route template, so verifying against it would drop the concrete segment out
// of the MAC the moment such a route lands. This route exists only in the test
// binary and is never part of Routes() or of the contract surface.
func NewWithProbeRouteForTest(cfg *config.Config, log *slog.Logger) *Server {
	s := New(cfg, log)
	s.echo.Add(http.MethodPost, "/probe/:id", s.authenticated(func(c *echo.Context, body []byte) error {
		return c.JSON(http.StatusOK, map[string]string{"id": c.Param("id")})
	}))
	return s
}
