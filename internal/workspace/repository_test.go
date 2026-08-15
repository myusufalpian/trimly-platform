package workspace

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
)

func TestNewRepository(t *testing.T) {
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewRepository(mock)
	if repo == nil {
		t.Error("expected repository, got nil")
	}
}

func TestCreateWorkspace(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO workspaces").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "created_by", "created_at", "updated_at"}).
				AddRow("ws-1", "Test Workspace", "user-1", now, now))
		mock.ExpectExec("INSERT INTO workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		ws, err := repo.CreateWorkspace(ctx, "Test Workspace", "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if ws.ID != "ws-1" {
			t.Errorf("expected ws-1, got %s", ws.ID)
		}
		if ws.Name != "Test Workspace" {
			t.Errorf("expected Test Workspace, got %s", ws.Name)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO workspaces").
			WillReturnError(errors.New("database error"))
		mock.ExpectRollback()

		_, err = repo.CreateWorkspace(ctx, "Test Workspace", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetUserWorkspaces(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM workspaces w JOIN workspace_members").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "created_by", "created_at", "updated_at"}).
				AddRow("ws-1", "Workspace 1", "user-1", now, now).
				AddRow("ws-2", "Workspace 2", "user-1", now, now))

		workspaces, err := repo.GetUserWorkspaces(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(workspaces) != 2 {
			t.Errorf("expected 2 workspaces, got %d", len(workspaces))
		}
	})

	t.Run("no workspaces", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM workspaces w JOIN workspace_members").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "created_by", "created_at", "updated_at"}))

		workspaces, err := repo.GetUserWorkspaces(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(workspaces) != 0 {
			t.Errorf("expected 0 workspaces, got %d", len(workspaces))
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM workspaces w JOIN workspace_members").
			WillReturnError(errors.New("database error"))

		_, err = repo.GetUserWorkspaces(ctx, "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetMemberRole(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT role FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"role"}).
				AddRow("OWNER"))

		role, err := repo.GetMemberRole(ctx, "ws-1", "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if role != RoleOwner {
			t.Errorf("expected OWNER, got %s", role)
		}
	})

	t.Run("member not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT role FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetMemberRole(ctx, "ws-1", "user-999")
		if !errors.Is(err, ErrMemberNotFound) {
			t.Errorf("expected ErrMemberNotFound, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT role FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		_, err = repo.GetMemberRole(ctx, "ws-1", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestAddMemberByEmail(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT id FROM users WHERE email").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id"}).
				AddRow("user-2"))
		mock.ExpectExec("INSERT INTO workspace_members.*ON CONFLICT").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.AddMemberByEmail(ctx, "ws-1", "user2@example.com", RoleMember)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT id FROM users WHERE email").
			WillReturnError(pgx.ErrNoRows)

		err = repo.AddMemberByEmail(ctx, "ws-1", "notfound@example.com", RoleMember)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT id FROM users WHERE email").
			WillReturnError(errors.New("database error"))

		err = repo.AddMemberByEmail(ctx, "ws-1", "user2@example.com", RoleMember)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestRemoveMemberOrLeave(t *testing.T) {
	ctx := context.Background()

	t.Run("member leaves", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT role FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"role"}).
				AddRow("MEMBER"))
		mock.ExpectExec("DELETE FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectCommit()

		err = repo.RemoveMemberOrLeave(ctx, "ws-1", "user-2")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("sole owner with members", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT role FROM workspace_members").
			WillReturnRows(pgxmock.NewRows([]string{"role"}).
				AddRow("OWNER"))
		mock.ExpectQuery("SELECT COUNT.*FROM workspace_members WHERE.*role = 'OWNER'").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(1))
		mock.ExpectQuery("SELECT COUNT.*FROM workspace_members WHERE workspace_id").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(3))
		mock.ExpectRollback()

		err = repo.RemoveMemberOrLeave(ctx, "ws-1", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("sole owner sole member", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT role FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"role"}).
				AddRow("OWNER"))
		mock.ExpectQuery("SELECT COUNT.*FROM workspace_members WHERE.*role = 'OWNER'").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(1))
		mock.ExpectQuery("SELECT COUNT.*FROM workspace_members WHERE workspace_id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(1))
		mock.ExpectExec("UPDATE workspaces SET deleted_at").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM workspace_members").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectCommit()

		err = repo.RemoveMemberOrLeave(ctx, "ws-1", "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT role FROM workspace_members").
			WillReturnError(errors.New("database error"))
		mock.ExpectRollback()

		err = repo.RemoveMemberOrLeave(ctx, "ws-1", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
