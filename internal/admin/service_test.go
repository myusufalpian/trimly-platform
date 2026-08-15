package admin

import (
	"context"
	"errors"
	"testing"

	"trimly-platform/internal/auth"
)

type mockAdminRepo struct {
	users              []auth.User
	listUsersErr       error
	addBlacklistErr    error
	removeBlacklistErr error
	isBlacklisted      bool
	unflagErr          error
}

func (m *mockAdminRepo) ListUsers(ctx context.Context) ([]auth.User, error) {
	return m.users, m.listUsersErr
}

func (m *mockAdminRepo) AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error {
	return m.addBlacklistErr
}

func (m *mockAdminRepo) RemoveBlacklistDomain(ctx context.Context, domain string) error {
	return m.removeBlacklistErr
}

func (m *mockAdminRepo) IsDomainBlacklisted(ctx context.Context, domain string) bool {
	return m.isBlacklisted
}

func (m *mockAdminRepo) UnflagClick(ctx context.Context, clickID string) error {
	return m.unflagErr
}

func TestServiceListUsers(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAdminRepo{
			users: []auth.User{
				{ID: "user-1", Email: "user1@example.com"},
				{ID: "user-2", Email: "user2@example.com"},
			},
		}
		svc := NewService(repo)

		users, err := svc.ListUsers(context.Background())
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(users) != 2 {
			t.Errorf("expected 2 users, got %d", len(users))
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAdminRepo{listUsersErr: errors.New("database error")}
		svc := NewService(repo)

		_, err := svc.ListUsers(context.Background())
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceAddBlacklistDomain(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAdminRepo{}
		svc := NewService(repo)

		err := svc.AddBlacklistDomain(context.Background(), "evil.com", "phishing", "admin-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("empty domain", func(t *testing.T) {
		repo := &mockAdminRepo{}
		svc := NewService(repo)

		err := svc.AddBlacklistDomain(context.Background(), "", "phishing", "admin-1")
		if !errors.Is(err, ErrDomainRequired) {
			t.Errorf("expected ErrDomainRequired, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAdminRepo{addBlacklistErr: errors.New("database error")}
		svc := NewService(repo)

		err := svc.AddBlacklistDomain(context.Background(), "evil.com", "phishing", "admin-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceRemoveBlacklistDomain(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAdminRepo{}
		svc := NewService(repo)

		err := svc.RemoveBlacklistDomain(context.Background(), "evil.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAdminRepo{removeBlacklistErr: errors.New("database error")}
		svc := NewService(repo)

		err := svc.RemoveBlacklistDomain(context.Background(), "evil.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceIsDomainBlacklisted(t *testing.T) {
	t.Run("blacklisted", func(t *testing.T) {
		repo := &mockAdminRepo{isBlacklisted: true}
		svc := NewService(repo)

		result := svc.IsDomainBlacklisted(context.Background(), "evil.com")
		if !result {
			t.Error("expected true, got false")
		}
	})

	t.Run("not blacklisted", func(t *testing.T) {
		repo := &mockAdminRepo{isBlacklisted: false}
		svc := NewService(repo)

		result := svc.IsDomainBlacklisted(context.Background(), "good.com")
		if result {
			t.Error("expected false, got true")
		}
	})
}

func TestServiceUnflagClick(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAdminRepo{}
		svc := NewService(repo)

		err := svc.UnflagClick(context.Background(), "click-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("empty click ID", func(t *testing.T) {
		repo := &mockAdminRepo{}
		svc := NewService(repo)

		err := svc.UnflagClick(context.Background(), "")
		if !errors.Is(err, ErrClickIDRequired) {
			t.Errorf("expected ErrClickIDRequired, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAdminRepo{unflagErr: errors.New("database error")}
		svc := NewService(repo)

		err := svc.UnflagClick(context.Background(), "click-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
