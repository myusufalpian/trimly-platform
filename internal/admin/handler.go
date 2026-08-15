package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type adminService interface {
	ListUsers(ctx context.Context) ([]auth.User, error)
	AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error
	RemoveBlacklistDomain(ctx context.Context, domain string) error
	UnflagClick(ctx context.Context, clickID string) error
}

type Handler struct {
	service adminService
}

func NewHandler(service adminService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.service.ListUsers(r.Context())
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_USERS_FAILED", "unable to fetch users")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"users": users,
	})
}

func (h *Handler) AddBlacklistDomain(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	adminUser, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || adminUser == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	var req AddBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	err := h.service.AddBlacklistDomain(r.Context(), req.Domain, req.Reason, adminUser.ID)
	if err != nil {
		if errors.Is(err, ErrDomainRequired) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "ADD_BLACKLIST_FAILED", "unable to add blacklist domain")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Domain blacklisted successfully",
	})
}

func (h *Handler) RemoveBlacklistDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/v1/admin/blacklist-domains/")
	domain = strings.TrimSpace(domain)
	if domain == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "domain path parameter is required")
		return
	}

	err := h.service.RemoveBlacklistDomain(r.Context(), domain)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "REMOVE_BLACKLIST_FAILED", "unable to remove blacklist domain")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Domain removed from blacklist successfully",
	})
}

func (h *Handler) UnflagClick(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req UnflagClickRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	err := h.service.UnflagClick(r.Context(), req.ClickID)
	if err != nil {
		if errors.Is(err, ErrClickIDRequired) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "UNFLAG_FAILED", "unable to unflag click")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Click unflagged successfully",
	})
}
