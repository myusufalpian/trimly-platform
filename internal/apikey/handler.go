package apikey

import (
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

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(auth.UserContextKey).(*auth.User)

	keyResp, err := h.service.CreateAPIKey(r.Context(), user)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "CREATE_KEY_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, keyResp)
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(auth.UserContextKey).(*auth.User)

	keys, err := h.service.GetUserAPIKeys(r.Context(), user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_KEYS_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"api_keys": keys,
	})
}

func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(auth.UserContextKey).(*auth.User)
	keyID := strings.TrimPrefix(r.URL.Path, "/v1/api-keys/")
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "key_id path parameter is required")
		return
	}

	err := h.service.RevokeAPIKey(r.Context(), keyID, user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "REVOKE_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "API key revoked successfully",
	})
}

func (h *Handler) GetUsageHistory(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(auth.UserContextKey).(*auth.User)

	history, err := h.service.GetAPIUsageHistory(r.Context(), user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_USAGE_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"api_usage": history,
	})
}
