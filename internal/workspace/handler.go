package workspace

import (
	"encoding/json"
	"net/http"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) CreateWorkspace(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user := r.Context().Value(auth.UserContextKey).(*auth.User)

	var req CreateWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	ws, err := h.service.CreateWorkspace(r.Context(), user.ID, req.Name)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "CREATE_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, ws)
}

func (h *Handler) ListWorkspaces(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(auth.UserContextKey).(*auth.User)

	workspaces, err := h.service.GetUserWorkspaces(r.Context(), user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"workspaces": workspaces,
	})
}

func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	workspaceID := r.URL.Query().Get("workspace_id")
	if workspaceID == "" {
		httputil.RespondError(w, http.StatusBadRequest, "MISSING_PARAM", "workspace_id query parameter is required")
		return
	}

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	err := h.service.AddMember(r.Context(), workspaceID, req.UserEmail, req.Role)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "ADD_MEMBER_FAILED", err.Error())
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Member added successfully",
	})
}
