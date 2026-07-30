package bio

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type Handler struct{ service *Service }

func NewHandler(service *Service) *Handler { return &Handler{service: service} }

func (h *Handler) CreatePage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	var req CreatePageRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}
	page, err := h.service.CreatePage(r.Context(), user, req)
	if err != nil {
		status := http.StatusBadRequest
		code := "CREATE_BIO_PAGE_FAILED"
		if errors.Is(err, ErrFreePageLimit) {
			status, code = http.StatusForbidden, "FORBIDDEN"
		}
		httputil.RespondError(w, status, code, err.Error())
		return
	}
	httputil.RespondJSON(w, http.StatusCreated, page)
}

func (h *Handler) AddLink(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	pageID := r.PathValue("id")
	var req AddLinkRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}
	if err := h.service.AddLink(r.Context(), user, pageID, req); err != nil {
		status := http.StatusBadRequest
		code := "ADD_BIO_LINK_FAILED"
		if errors.Is(err, ErrBioPageUnauthorized) || errors.Is(err, ErrBioLinkUnauthorized) {
			status, code = http.StatusForbidden, "FORBIDDEN"
		}
		if errors.Is(err, ErrBioPageNotFound) {
			status, code = http.StatusNotFound, "NOT_FOUND"
		}
		httputil.RespondError(w, status, code, err.Error())
		return
	}
	httputil.RespondJSON(w, http.StatusCreated, req)
}

func (h *Handler) PublicPage(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/bio-pages/public/"))
	if slug == "" {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_SLUG", "Bio page slug is required")
		return
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	page, err := h.service.GetPublicPage(r.Context(), slug, scheme+"://"+r.Host)
	if err != nil {
		httputil.RespondError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	httputil.RespondJSON(w, http.StatusOK, page)
}
