package bio

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type bioService interface {
	CreatePage(ctx context.Context, user *auth.User, req CreatePageRequest) (*Page, error)
	AddLink(ctx context.Context, user *auth.User, pageID string, req AddLinkRequest) error
	GetPublicPage(ctx context.Context, slug, baseURL string) (*PublicPage, error)
}

type Handler struct{ service bioService }

func NewHandler(service bioService) *Handler { return &Handler{service: service} }

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
		if errors.Is(err, ErrInvalidInput) {
			status, code = http.StatusBadRequest, "INVALID_INPUT"
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
	page, err := h.service.GetPublicPage(r.Context(), slug, httputil.BaseURL(r))
	if err != nil {
		httputil.RespondError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	httputil.RespondJSON(w, http.StatusOK, page)
}
