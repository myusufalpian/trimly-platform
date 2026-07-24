package workspace_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	err := svc.AddMember(context.Background(), "ws-1", "", workspace.RoleMember)
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
