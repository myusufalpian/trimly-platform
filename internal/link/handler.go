package link

import (
	"encoding/json"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) CreateLink(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user := r.Context().Value(auth.UserContextKey).(*auth.User)

	var req CreateLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	link, err := h.service.CreateLink(r.Context(), user, req)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "CREATE_LINK_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, link)
}

func (h *Handler) PublicRedirect(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/r/")
	slug = strings.TrimSpace(slug)
	if slug == "" {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_SLUG", "Shortlink slug is required")
		return
	}

	targetURL, err := h.service.ResolveAndRecordRedirect(r.Context(), slug, "DIRECT")
	if err != nil {
		httputil.RespondError(w, http.StatusNotFound, "LINK_NOT_FOUND", err.Error())
		return
	}

	http.Redirect(w, r, targetURL, http.StatusFound)
}

func (h *Handler) GetAnalytics(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(auth.UserContextKey).(*auth.User)
	linkID := r.URL.Query().Get("link_id")
	if linkID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "link_id query parameter is required")
		return
	}

	analytics, err := h.service.GetAnalytics(r.Context(), user, linkID)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "FETCH_ANALYTICS_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, analytics)
}
