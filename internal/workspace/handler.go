package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type workspaceService interface {
	CreateWorkspace(ctx context.Context, userID, name string) (*Workspace, error)
	GetUserWorkspaces(ctx context.Context, userID string) ([]Workspace, error)
	AddMember(ctx context.Context, workspaceID, callerID, email string, role Role) error
}

type Handler struct {
	service workspaceService
}

func NewHandler(service workspaceService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) CreateWorkspace(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	var req CreateWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	ws, err := h.service.CreateWorkspace(r.Context(), user.ID, req.Name)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "CREATE_FAILED", "unable to create workspace")
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, ws)
}

func (h *Handler) ListWorkspaces(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	workspaces, err := h.service.GetUserWorkspaces(r.Context(), user.ID)
	if err != nil {
		httputil.RespondError(w, http.StatusInternalServerError, "FETCH_FAILED", "unable to fetch workspaces")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"workspaces": workspaces,
	})
}

func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
	if !ok || user == nil {
		httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
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

	err := h.service.AddMember(r.Context(), workspaceID, user.ID, req.UserEmail, req.Role)
	if err != nil {
		if errors.Is(err, ErrInsufficientPermission) {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", "insufficient workspace permissions")
			return
		}
		if errors.Is(err, ErrInvalidInput) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusInternalServerError, "ADD_MEMBER_FAILED", "unable to add member")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Member added successfully",
	})
}
