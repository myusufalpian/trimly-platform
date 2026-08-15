package apikey

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type apiKeyService interface {
	CreateAPIKey(ctx context.Context, user *auth.User) (*APIKeyResponse, error)
	GetUserAPIKeys(ctx context.Context, userID string) ([]APIKeyResponse, error)
	RevokeAPIKey(ctx context.Context, keyID, userID string) error
	GetAPIUsageHistory(ctx context.Context, userID string) ([]APIUsageDaily, error)
}

type Handler struct {
	service apiKeyService
}

func NewHandler(service apiKeyService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	keyResp, err := h.service.CreateAPIKey(r.Context(), user)
	if err != nil {
		if errors.Is(err, ErrBusinessPlanRequired) {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "CREATE_KEY_FAILED", "unable to create API key")
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, keyResp)
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	keys, err := h.service.GetUserAPIKeys(r.Context(), user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_KEYS_FAILED", "unable to fetch API keys")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"api_keys": keys,
	})
}

func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	keyID := strings.TrimPrefix(r.URL.Path, "/v1/api-keys/")
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "key_id path parameter is required")
		return
	}

	err := h.service.RevokeAPIKey(r.Context(), keyID, user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "REVOKE_FAILED", "unable to revoke API key")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "API key revoked successfully",
	})
}

func (h *Handler) GetUsageHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	history, err := h.service.GetAPIUsageHistory(r.Context(), user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_USAGE_FAILED", "unable to fetch usage history")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"api_usage": history,
	})
}
