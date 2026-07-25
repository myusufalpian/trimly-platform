package admin

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

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.service.ListUsers(r.Context())
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_USERS_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"users": users,
	})
}

func (h *Handler) AddBlacklistDomain(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	adminUser := r.Context().Value(auth.UserContextKey).(*auth.User)

	var req AddBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	err := h.service.AddBlacklistDomain(r.Context(), req.Domain, req.Reason, adminUser.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "ADD_BLACKLIST_FAILED", err.Error())
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
		httputil.RespondError(w, http.StatusBadRequest, "REMOVE_BLACKLIST_FAILED", err.Error())
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
		httputil.RespondError(w, http.StatusBadRequest, "UNFLAG_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Click unflagged successfully",
	})
}
