package workspace

import (
	"context"
	"errors"
	"net/http"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type workspaceRepository interface {
	CreateWorkspace(ctx context.Context, name, userID string) (*Workspace, error)
	GetUserWorkspaces(ctx context.Context, userID string) ([]Workspace, error)
	GetMemberRole(ctx context.Context, workspaceID, userID string) (Role, error)
	AddMemberByEmail(ctx context.Context, workspaceID, targetEmail string, role Role) error
	RemoveMemberOrLeave(ctx context.Context, workspaceID, targetUserID string) error
}

type Service struct {
	repo workspaceRepository
}

func NewService(repo workspaceRepository) *Service {
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

func (s *Service) AddMember(ctx context.Context, workspaceID, callerID, email string, role Role) error {
	if email == "" {
		return errors.New("email is required")
	}
	if role != RoleAdmin && role != RoleMember && role != RoleOwner {
		role = RoleMember
	}
	if err := s.CheckPermission(ctx, workspaceID, callerID, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	return s.repo.AddMemberByEmail(ctx, workspaceID, email, role)
}

func (s *Service) LeaveOrRemoveMember(ctx context.Context, workspaceID, userID string) error {
	return s.repo.RemoveMemberOrLeave(ctx, workspaceID, userID)
}

var ErrInsufficientPermission = errors.New("insufficient workspace permissions")

func (s *Service) CheckPermission(ctx context.Context, workspaceID, userID string, requiredRoles ...Role) error {
	userRole, err := s.repo.GetMemberRole(ctx, workspaceID, userID)
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return ErrInsufficientPermission
		}
		return err
	}

	for _, r := range requiredRoles {
		if userRole == r {
			return nil
		}
	}

	return ErrInsufficientPermission
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
