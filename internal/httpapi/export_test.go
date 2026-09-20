package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v5"
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
