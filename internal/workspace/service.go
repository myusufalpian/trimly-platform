package workspace

import (
	"context"
	"errors"
	"net/http"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) CreateWorkspace(ctx context.Context, userID, name string) (*Workspace, error) {
	if name == "" {
		return nil, errors.New("workspace name is required")
	}
	return s.repo.CreateWorkspace(ctx, name, userID)
}

func (s *Service) GetUserWorkspaces(ctx context.Context, userID string) ([]Workspace, error) {
	return s.repo.GetUserWorkspaces(ctx, userID)
}

func (s *Service) AddMember(ctx context.Context, workspaceID, email string, role Role) error {
	if email == "" {
		return errors.New("email is required")
	}
	if role != RoleAdmin && role != RoleMember && role != RoleOwner {
		role = RoleMember
	}
	return s.repo.AddMemberByEmail(ctx, workspaceID, email, role)
}

func (s *Service) LeaveOrRemoveMember(ctx context.Context, workspaceID, userID string) error {
	return s.repo.RemoveMemberOrLeave(ctx, workspaceID, userID)
}

func (s *Service) CheckPermission(ctx context.Context, workspaceID, userID string, requiredRoles ...Role) error {
	userRole, err := s.repo.GetMemberRole(ctx, workspaceID, userID)
	if err != nil {
		return err
	}

	for _, r := range requiredRoles {
		if userRole == r {
			return nil
		}
	}

	return errors.New("insufficient workspace permissions")
}

// RBAC Middleware Helper
func (s *Service) RequireWorkspaceRoleMiddleware(workspaceIDParam string, allowedRoles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
			if !ok || user == nil {
				httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
				return
			}

			// In real routing, workspaceID is extracted from URL path or Query
			workspaceID := r.URL.Query().Get("workspace_id")
			if workspaceID == "" {
				workspaceID = r.Header.Get("X-Workspace-ID")
			}

			if workspaceID != "" {
				err := s.CheckPermission(r.Context(), workspaceID, user.ID, allowedRoles...)
				if err != nil {
					httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
