package workspace_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/workspace"
)

func TestCreateWorkspaceValidation(t *testing.T) {
	svc := workspace.NewService(nil)

	_, err := svc.CreateWorkspace(context.Background(), "user-1", "")
	if err == nil {
		t.Fatalf("expected error for empty workspace name, got nil")
	}

	if err.Error() != "workspace name is required" {
		t.Errorf("expected error 'workspace name is required', got %q", err.Error())
	}
}

func TestAddMemberValidation(t *testing.T) {
	svc := workspace.NewService(nil)

	err := svc.AddMember(context.Background(), "ws-1", "user-1", "", workspace.RoleMember)
	if err == nil {
		t.Fatalf("expected error for empty email, got nil")
	}

	if err.Error() != "email is required" {
		t.Errorf("expected error 'email is required', got %q", err.Error())
	}
}

func TestRequireWorkspaceRoleMiddlewareUnauthenticated(t *testing.T) {
	svc := workspace.NewService(nil)
	middleware := svc.RequireWorkspaceRoleMiddleware("workspace_id", workspace.RoleOwner)

	req := httptest.NewRequest("GET", "/test-workspace", nil)
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for unauthenticated request, got %d", rr.Code)
	}
}

func TestRequireWorkspaceRoleMiddlewareAuthenticated(t *testing.T) {
	svc := workspace.NewService(nil)
	middleware := svc.RequireWorkspaceRoleMiddleware("workspace_id", workspace.RoleOwner)

	req := httptest.NewRequest("GET", "/test-workspace", nil)
	user := &auth.User{ID: "user-1", Email: "owner@trimly.app"}
	ctx := context.WithValue(req.Context(), auth.UserContextKey, user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// When workspace_id is absent from request, it passes through to nextHandler
	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK when no workspace_id specified, got %d", rr.Code)
	}
}

type stubWorkspaceRepo struct {
	memberRole       workspace.Role
	roleErr          error
	addErr           error
	addCalled        bool
	addedWorkspaceID string
	addedEmail       string
	addedRole        workspace.Role
}

func (s *stubWorkspaceRepo) CreateWorkspace(ctx context.Context, name, userID string) (*workspace.Workspace, error) {
	return &workspace.Workspace{ID: "ws-1", Name: name, CreatedBy: userID}, nil
}

func (s *stubWorkspaceRepo) GetUserWorkspaces(ctx context.Context, userID string) ([]workspace.Workspace, error) {
	return nil, nil
}

func (s *stubWorkspaceRepo) GetMemberRole(ctx context.Context, workspaceID, userID string) (workspace.Role, error) {
	if s.roleErr != nil {
		return "", s.roleErr
	}
	return s.memberRole, nil
}

func (s *stubWorkspaceRepo) AddMemberByEmail(ctx context.Context, workspaceID, targetEmail string, role workspace.Role) error {
	s.addCalled = true
	s.addedWorkspaceID = workspaceID
	s.addedEmail = targetEmail
	s.addedRole = role
	return s.addErr
}

func (s *stubWorkspaceRepo) RemoveMemberOrLeave(ctx context.Context, workspaceID, targetUserID string) error {
	return nil
}

func TestAddMemberRequiresOwnerOrAdmin(t *testing.T) {
	t.Run("Member is rejected", func(t *testing.T) {
		repo := &stubWorkspaceRepo{memberRole: workspace.RoleMember}
		svc := workspace.NewService(repo)

		err := svc.AddMember(context.Background(), "ws-1", "caller-1", "guest@test.com", workspace.RoleMember)
		if err == nil || err.Error() != "insufficient workspace permissions" {
			t.Fatalf("expected insufficient permissions error, got %v", err)
		}
		if repo.addCalled {
			t.Errorf("AddMemberByEmail must not be called without permission")
		}
	})

	t.Run("Owner is permitted", func(t *testing.T) {
		repo := &stubWorkspaceRepo{memberRole: workspace.RoleOwner}
		svc := workspace.NewService(repo)

		err := svc.AddMember(context.Background(), "ws-1", "caller-1", "guest@test.com", workspace.RoleOwner)
		if err != nil {
			t.Fatalf("expected no error for owner caller, got %v", err)
		}
		if !repo.addCalled {
			t.Fatal("expected AddMemberByEmail to be called for owner caller")
		}
		if repo.addedEmail != "guest@test.com" || repo.addedRole != workspace.RoleOwner || repo.addedWorkspaceID != "ws-1" {
			t.Errorf("unexpected add arguments: email=%q role=%q workspace=%q", repo.addedEmail, repo.addedRole, repo.addedWorkspaceID)
		}
	})

	t.Run("Admin is permitted", func(t *testing.T) {
		repo := &stubWorkspaceRepo{memberRole: workspace.RoleAdmin}
		svc := workspace.NewService(repo)

		err := svc.AddMember(context.Background(), "ws-1", "caller-1", "guest@test.com", workspace.RoleMember)
		if err != nil {
			t.Fatalf("expected no error for admin caller, got %v", err)
		}
		if !repo.addCalled {
			t.Fatal("expected AddMemberByEmail to be called for admin caller")
		}
	})
}

func TestAddMemberDefaultsUnknownRoleToMember(t *testing.T) {
	repo := &stubWorkspaceRepo{memberRole: workspace.RoleOwner}
	svc := workspace.NewService(repo)

	err := svc.AddMember(context.Background(), "ws-1", "caller-1", "guest@test.com", workspace.Role("SUPERUSER"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.addedRole != workspace.RoleMember {
		t.Errorf("expected role defaulted to MEMBER, got %q", repo.addedRole)
	}
}

func TestAddMemberRequiresEmail(t *testing.T) {
	repo := &stubWorkspaceRepo{memberRole: workspace.RoleOwner}
	svc := workspace.NewService(repo)

	err := svc.AddMember(context.Background(), "ws-1", "caller-1", "", workspace.RoleMember)
	if err == nil || err.Error() != "email is required" {
		t.Fatalf("expected email required error, got %v", err)
	}
	if repo.addCalled {
		t.Errorf("AddMemberByEmail must not be called when email is empty")
	}
}

func TestAddMemberNonMemberRoleLookupError(t *testing.T) {
	repo := &stubWorkspaceRepo{roleErr: workspace.ErrMemberNotFound}
	svc := workspace.NewService(repo)

	err := svc.AddMember(context.Background(), "ws-1", "caller-1", "guest@test.com", workspace.RoleMember)
	if err != workspace.ErrInsufficientPermission {
		t.Fatalf("expected ErrInsufficientPermission, got %v", err)
	}
	if repo.addCalled {
		t.Errorf("AddMemberByEmail must not be called when caller has no role")
	}
}

func TestCheckPermissionPropagatesInfraError(t *testing.T) {
	infraErr := errors.New("connection refused")
	repo := &stubWorkspaceRepo{roleErr: infraErr}
	svc := workspace.NewService(repo)

	err := svc.CheckPermission(context.Background(), "ws-1", "caller-1", workspace.RoleOwner)
	if err != infraErr {
		t.Fatalf("expected infra error to propagate, got %v", err)
	}
}

func TestCheckPermissionRejectsWrongRole(t *testing.T) {
	repo := &stubWorkspaceRepo{memberRole: workspace.RoleMember}
	svc := workspace.NewService(repo)

	err := svc.CheckPermission(context.Background(), "ws-1", "caller-1", workspace.RoleOwner)
	if err != workspace.ErrInsufficientPermission {
		t.Fatalf("expected ErrInsufficientPermission, got %v", err)
	}
}

func TestRequireWorkspaceRoleMiddlewareForbidsNonOwner(t *testing.T) {
	repo := &stubWorkspaceRepo{memberRole: workspace.RoleMember}
	svc := workspace.NewService(repo)
	middleware := svc.RequireWorkspaceRoleMiddleware("workspace_id", workspace.RoleOwner)

	req := httptest.NewRequest("GET", "/test?workspace_id=ws-1", nil)
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1"})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-owner, got %d", rr.Code)
	}
}

type stubWorkspaceService struct {
	addMemberErr  error
	addedCallerID string
	addedEmail    string
	addedRole     workspace.Role
	addedWsID     string
}

func (s *stubWorkspaceService) CreateWorkspace(ctx context.Context, userID, name string) (*workspace.Workspace, error) {
	return nil, nil
}

func (s *stubWorkspaceService) GetUserWorkspaces(ctx context.Context, userID string) ([]workspace.Workspace, error) {
	return nil, nil
}

func (s *stubWorkspaceService) AddMember(ctx context.Context, workspaceID, callerID, email string, role workspace.Role) error {
	s.addedCallerID = callerID
	s.addedEmail = email
	s.addedRole = role
	s.addedWsID = workspaceID
	return s.addMemberErr
}

func withUser(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), auth.UserContextKey, &auth.User{ID: userID, Email: "caller@test.com"})
	return r.WithContext(ctx)
}

func TestAddMemberHandlerRequiresAuthentication(t *testing.T) {
	handler := workspace.NewHandler(&stubWorkspaceService{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/workspaces/members?workspace_id=ws-1", strings.NewReader(`{"user_email":"guest@test.com","role":"OWNER"}`))

	handler.AddMember(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without user in context, got %d", rr.Code)
	}
}

func TestAddMemberHandlerForbiddenWithoutPermission(t *testing.T) {
	handler := workspace.NewHandler(&stubWorkspaceService{addMemberErr: workspace.ErrInsufficientPermission})
	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest("POST", "/v1/workspaces/members?workspace_id=ws-1", strings.NewReader(`{"user_email":"guest@test.com","role":"OWNER"}`)), "caller-1")

	handler.AddMember(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", rr.Code)
	}
}

func TestAddMemberHandlerMissingWorkspaceID(t *testing.T) {
	handler := workspace.NewHandler(&stubWorkspaceService{})
	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest("POST", "/v1/workspaces/members", strings.NewReader(`{"user_email":"guest@test.com"}`)), "caller-1")

	handler.AddMember(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for missing workspace_id, got %d", rr.Code)
	}
}

func TestAddMemberHandlerSuccess(t *testing.T) {
	svc := &stubWorkspaceService{}
	handler := workspace.NewHandler(svc)
	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest("POST", "/v1/workspaces/members?workspace_id=ws-1", strings.NewReader(`{"user_email":"guest@test.com","role":"OWNER"}`)), "caller-1")

	handler.AddMember(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	if svc.addedCallerID != "caller-1" {
		t.Errorf("expected caller ID forwarded, got %q", svc.addedCallerID)
	}
	if svc.addedEmail != "guest@test.com" || svc.addedRole != workspace.RoleOwner || svc.addedWsID != "ws-1" {
		t.Errorf("unexpected add member args: email=%q role=%q workspace=%q", svc.addedEmail, svc.addedRole, svc.addedWsID)
	}
}

func TestAddMemberHandlerBusinessError(t *testing.T) {
	handler := workspace.NewHandler(&stubWorkspaceService{addMemberErr: errors.New("unable to add member to workspace")})
	rr := httptest.NewRecorder()
	req := withUser(httptest.NewRequest("POST", "/v1/workspaces/members?workspace_id=ws-1", strings.NewReader(`{"user_email":"guest@test.com"}`)), "caller-1")

	handler.AddMember(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for business error, got %d", rr.Code)
	}
}
