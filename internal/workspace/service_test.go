package workspace

import (
	"context"
	"errors"
	"testing"
)

type mockWorkspaceRepo struct {
	workspaces       []Workspace
	getWorkspacesErr error
	createWs         *Workspace
	createWsErr      error
	memberRole       Role
	getRoleErr       error
	addMemberErr     error
	removeErr        error
}

func (m *mockWorkspaceRepo) CreateWorkspace(ctx context.Context, name, userID string) (*Workspace, error) {
	return m.createWs, m.createWsErr
}

func (m *mockWorkspaceRepo) GetUserWorkspaces(ctx context.Context, userID string) ([]Workspace, error) {
	return m.workspaces, m.getWorkspacesErr
}

func (m *mockWorkspaceRepo) GetMemberRole(ctx context.Context, workspaceID, userID string) (Role, error) {
	return m.memberRole, m.getRoleErr
}

func (m *mockWorkspaceRepo) AddMemberByEmail(ctx context.Context, workspaceID, targetEmail string, role Role) error {
	return m.addMemberErr
}

func (m *mockWorkspaceRepo) RemoveMemberOrLeave(ctx context.Context, workspaceID, targetUserID string) error {
	return m.removeErr
}

func TestServiceGetUserWorkspaces(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockWorkspaceRepo{
			workspaces: []Workspace{
				{ID: "ws-1", Name: "Workspace 1"},
				{ID: "ws-2", Name: "Workspace 2"},
			},
		}
		svc := NewService(repo)

		workspaces, err := svc.GetUserWorkspaces(context.Background(), "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(workspaces) != 2 {
			t.Errorf("expected 2 workspaces, got %d", len(workspaces))
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockWorkspaceRepo{getWorkspacesErr: errors.New("database error")}
		svc := NewService(repo)

		_, err := svc.GetUserWorkspaces(context.Background(), "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceLeaveOrRemoveMember(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockWorkspaceRepo{}
		svc := NewService(repo)

		err := svc.LeaveOrRemoveMember(context.Background(), "ws-1", "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockWorkspaceRepo{removeErr: errors.New("database error")}
		svc := NewService(repo)

		err := svc.LeaveOrRemoveMember(context.Background(), "ws-1", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceCreateWorkspace(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockWorkspaceRepo{
			createWs: &Workspace{ID: "ws-1", Name: "Test Workspace"},
		}
		svc := NewService(repo)

		ws, err := svc.CreateWorkspace(context.Background(), "user-1", "Test Workspace")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if ws == nil {
			t.Fatal("expected workspace, got nil")
		}
		if ws.ID != "ws-1" {
			t.Errorf("expected ws-1, got %s", ws.ID)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		repo := &mockWorkspaceRepo{}
		svc := NewService(repo)

		_, err := svc.CreateWorkspace(context.Background(), "user-1", "")
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockWorkspaceRepo{createWsErr: errors.New("database error")}
		svc := NewService(repo)

		_, err := svc.CreateWorkspace(context.Background(), "user-1", "Test Workspace")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
