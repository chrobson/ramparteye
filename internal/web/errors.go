package web

import (
	"net/http"

	"github.com/chrobson/ramparteye/internal/auth"
)

// errorData is the data of the error page.
type errorData struct {
	Code  int
	Title string
	Text  string
}

// renderError writes the themed error page; API and htmx requests get a
// plain text body. If the page itself fails, a plain error is written.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, e errorData) {
	if auth.IsAPIRequest(r) {
		http.Error(w, e.Text, e.Code)
		return
	}
	if err := s.execute(w, r, e.Code, "error", e); err != nil {
		s.log.Error("render error page", "path", r.URL.Path, "err", err)
		http.Error(w, e.Title, e.Code)
	}
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, errorData{Code: http.StatusNotFound, Title: "Page not found",
		Text: "The page you asked for does not exist."})
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, errorData{Code: http.StatusMethodNotAllowed, Title: "Method not allowed",
		Text: "This page does not accept that kind of request."})
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request, perm auth.Perm) {
	s.renderError(w, r, errorData{Code: http.StatusForbidden, Title: "Access denied",
		Text: "Your role does not include the " + string(perm) + " permission. Ask an administrator if you need it."})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, errorData{Code: http.StatusInternalServerError, Title: "Something went wrong",
		Text: "The error has been logged. Try again, or go back to the dashboard."})
}
