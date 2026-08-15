package link

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type linkService interface {
	CreateLink(ctx context.Context, user *auth.User, req CreateLinkRequest) (*Link, error)
	ResolveAndRecordRedirect(ctx context.Context, slug, source string) (string, error)
	GetAnalytics(ctx context.Context, user *auth.User, linkID string) (*AnalyticsSummary, error)
	GenerateQRCode(ctx context.Context, user *auth.User, linkID, baseURL string) ([]byte, error)
	ExportCSVAnalytics(ctx context.Context, user *auth.User, linkID string) ([]byte, error)
}

type Handler struct {
	service linkService
}

func NewHandler(service linkService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) CreateLink(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	var req CreateLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	link, err := h.service.CreateLink(r.Context(), user, req)
	if err != nil {
		if errors.Is(err, ErrMaliciousURL) {
			httputil.RespondError(w, http.StatusBadRequest, "MALICIOUS_URL_DETECTED", "The provided target URL poses a security threat and cannot be shortened.")
			return
		}
		if errors.Is(err, ErrCustomDomainPlan) || errors.Is(err, ErrWorkspaceForbidden) {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
		if errors.Is(err, ErrInvalidInput) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "CREATE_LINK_FAILED", "unable to create shortlink")
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, link)
}

func (h *Handler) PublicRedirect(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		slug = trimRedirectSlug(r.URL.Path)
	}
	if slug == "" {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_SLUG", "Shortlink slug is required")
		return
	}

	targetURL, err := h.service.ResolveAndRecordRedirect(r.Context(), slug, "DIRECT")
	if err != nil {
		if errors.Is(err, ErrMaliciousURL) {
			httputil.RespondError(w, http.StatusBadRequest, "MALICIOUS_URL_DETECTED", "This link is blocked because it leads to a malicious or blacklisted domain")
			return
		}
		httputil.RespondError(w, http.StatusNotFound, "LINK_NOT_FOUND", "shortlink not found")
		return
	}

	http.Redirect(w, r, targetURL, http.StatusFound)
}

func trimRedirectSlug(path string) string {
	s := path
	if len(s) > 3 && s[:3] == "/r/" {
		s = s[3:]
	}
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

func (h *Handler) GetAnalytics(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	linkID := r.URL.Query().Get("link_id")
	if linkID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "link_id query parameter is required")
		return
	}

	analytics, err := h.service.GetAnalytics(r.Context(), user, linkID)
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			httputil.RespondError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		if errors.Is(err, ErrLinkUnauthorized) {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_ANALYTICS_FAILED", "unable to fetch analytics")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, analytics)
}

func (h *Handler) GenerateQRCode(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	linkID := r.URL.Query().Get("link_id")
	if linkID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "link_id query parameter is required")
		return
	}

	pngBytes, err := h.service.GenerateQRCode(r.Context(), user, linkID, httputil.BaseURL(r))
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			httputil.RespondError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		if errors.Is(err, ErrLinkUnauthorized) {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "QR_GENERATE_FAILED", "unable to generate QR code")
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pngBytes)
}

func (h *Handler) ExportCSVAnalytics(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	linkID := r.URL.Query().Get("link_id")
	if linkID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "link_id query parameter is required")
		return
	}

	csvBytes, err := h.service.ExportCSVAnalytics(r.Context(), user, linkID)
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			httputil.RespondError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		if errors.Is(err, ErrLinkUnauthorized) || errors.Is(err, ErrCSVPlan) {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "EXPORT_FAILED", "unable to export analytics")
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="analytics_report.csv"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(csvBytes)
}
