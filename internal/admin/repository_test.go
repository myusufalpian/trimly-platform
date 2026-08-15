package admin

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

func TestListUsers(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM users").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("user-1", "user1@example.com", "FREE", false, now, now).
				AddRow("user-2", "user2@example.com", "PRO", false, now, now))

		users, err := repo.ListUsers(ctx)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(users) != 2 {
			t.Errorf("expected 2 users, got %d", len(users))
		}
	})

	t.Run("no users", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM users").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "plan_code", "is_platform_admin", "created_at", "updated_at"}))

		users, err := repo.ListUsers(ctx)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(users) != 0 {
			t.Errorf("expected 0 users, got %d", len(users))
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM users").
			WillReturnError(errors.New("database error"))

		_, err = repo.ListUsers(ctx)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestAddBlacklistDomain(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("INSERT INTO blacklisted_domains").
			WithArgs("evil.com", "phishing", "admin-1").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.AddBlacklistDomain(ctx, "evil.com", "phishing", "admin-1")
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

		mock.ExpectExec("INSERT INTO blacklisted_domains").
			WillReturnError(errors.New("database error"))

		err = repo.AddBlacklistDomain(ctx, "evil.com", "phishing", "admin-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestRemoveBlacklistDomain(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("DELETE FROM blacklisted_domains WHERE domain").
			WithArgs("evil.com").
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err = repo.RemoveBlacklistDomain(ctx, "evil.com")
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

		mock.ExpectExec("DELETE FROM blacklisted_domains WHERE domain").
			WillReturnError(errors.New("database error"))

		err = repo.RemoveBlacklistDomain(ctx, "evil.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestIsDomainBlacklisted(t *testing.T) {
	ctx := context.Background()

	t.Run("blacklisted", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT 1 FROM blacklisted_domains WHERE domain").
			WithArgs("evil.com").
			WillReturnRows(pgxmock.NewRows([]string{"1"}).
				AddRow(1))

		blacklisted := repo.IsDomainBlacklisted(ctx, "evil.com")
		if !blacklisted {
			t.Error("expected domain to be blacklisted")
		}
	})

	t.Run("not blacklisted", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT 1 FROM blacklisted_domains WHERE domain").
			WillReturnError(pgx.ErrNoRows)

		blacklisted := repo.IsDomainBlacklisted(ctx, "good.com")
		if blacklisted {
			t.Error("expected domain to not be blacklisted")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT 1 FROM blacklisted_domains WHERE domain").
			WillReturnError(errors.New("database error"))

		blacklisted := repo.IsDomainBlacklisted(ctx, "evil.com")
		if blacklisted {
			t.Error("expected false on database error")
		}
	})
}

func TestUnflagClick(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("UPDATE click_events SET flagged = false").
			WithArgs("click-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err = repo.UnflagClick(ctx, "click-1")
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

		mock.ExpectExec("UPDATE click_events SET flagged = false").
			WillReturnError(errors.New("database error"))

		err = repo.UnflagClick(ctx, "click-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
