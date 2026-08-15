package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

func TestHashToken(t *testing.T) {
	hash1 := HashToken("test-token")
	hash2 := HashToken("test-token")

	if hash1 != hash2 {
		t.Error("expected deterministic hash")
	}

	if hash1 == "" {
		t.Error("expected non-empty hash")
	}
}

func TestCreateUserWithPlan(t *testing.T) {
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
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("user-1", "test@example.com", "FREE", false, now, now))
		mock.ExpectExec("INSERT INTO plan_usage").
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		user, err := repo.CreateUserWithPlan(ctx, "test@example.com", "hashed-password")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %s", user.ID)
		}
		if user.Email != "test@example.com" {
			t.Errorf("expected test@example.com, got %s", user.Email)
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(&pgconn.PgError{Code: "23505"})
		mock.ExpectRollback()

		_, err = repo.CreateUserWithPlan(ctx, "test@example.com", "hashed-password")
		if !errors.Is(err, ErrEmailTaken) {
			t.Errorf("expected ErrEmailTaken, got %v", err)
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
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(errors.New("connection failed"))
		mock.ExpectRollback()
		_, err = repo.CreateUserWithPlan(ctx, "test@example.com", "hashed-password")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("plan usage error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO users").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("user-1", "test@example.com", "FREE", false, now, now))
		mock.ExpectExec("INSERT INTO plan_usage").
			WillReturnError(errors.New("plan usage error"))
		mock.ExpectRollback()

		_, err = repo.CreateUserWithPlan(ctx, "test@example.com", "hashed-password")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestSaveVerificationToken(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		expiresAt := time.Now().Add(24 * time.Hour)

		mock.ExpectExec("INSERT INTO email_verification_tokens").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.SaveVerificationToken(ctx, "user-1", "raw-token", expiresAt)
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
		expiresAt := time.Now().Add(24 * time.Hour)

		mock.ExpectExec("INSERT INTO email_verification_tokens").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		err = repo.SaveVerificationToken(ctx, "user-1", "raw-token", expiresAt)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestVerifyEmailToken(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		futureTime := time.Now().Add(24 * time.Hour)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, expires_at, consumed_at").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "expires_at", "consumed_at"}).
				AddRow("user-1", futureTime, nil))
		mock.ExpectExec("UPDATE email_verification_tokens").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		err = repo.VerifyEmailToken(ctx, "raw-token")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("token not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, expires_at, consumed_at").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		err = repo.VerifyEmailToken(ctx, "invalid-token")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("token already consumed", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		consumedAt := time.Now().Add(-1 * time.Hour)
		futureTime := time.Now().Add(24 * time.Hour)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, expires_at, consumed_at").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "expires_at", "consumed_at"}).
				AddRow("user-1", futureTime, &consumedAt))
		mock.ExpectRollback()

		err = repo.VerifyEmailToken(ctx, "raw-token")
		if err == nil {
			t.Error("expected error for consumed token, got nil")
		}
	})

	t.Run("token expired", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		pastTime := time.Now().Add(-24 * time.Hour)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, expires_at, consumed_at").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "expires_at", "consumed_at"}).
				AddRow("user-1", pastTime, nil))
		mock.ExpectRollback()

		err = repo.VerifyEmailToken(ctx, "raw-token")
		if err == nil {
			t.Error("expected error for expired token, got nil")
		}
	})

	t.Run("update token error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		futureTime := time.Now().Add(24 * time.Hour)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, expires_at, consumed_at").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "expires_at", "consumed_at"}).
				AddRow("user-1", futureTime, nil))
		mock.ExpectExec("UPDATE email_verification_tokens").
			WillReturnError(errors.New("update error"))
		mock.ExpectRollback()

		err = repo.VerifyEmailToken(ctx, "raw-token")
		if err == nil {
			t.Error("expected error for update token, got nil")
		}
	})
}

func TestGetUserByEmail(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM users WHERE email").
			WithArgs("test@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "email_verified_at", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("user-1", "test@example.com", "hash", nil, "FREE", false, now, now))

		user, err := repo.GetUserByEmail(ctx, "test@example.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %s", user.ID)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM users WHERE email").
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetUserByEmail(ctx, "notfound@example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetUserByID(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM users WHERE id").
			WithArgs("user-1").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "email_verified_at", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("user-1", "test@example.com", "hash", nil, "FREE", false, now, now))

		user, err := repo.GetUserByID(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %s", user.ID)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM users WHERE id").
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetUserByID(ctx, "notfound")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestCreateSession(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		expiresAt := time.Now().Add(7 * 24 * time.Hour)

		mock.ExpectExec("INSERT INTO sessions").
			WithArgs("user-1", pgxmock.AnyArg(), expiresAt).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.CreateSession(ctx, "user-1", "raw-token", expiresAt)
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
		expiresAt := time.Now().Add(7 * 24 * time.Hour)

		mock.ExpectExec("INSERT INTO sessions").
			WillReturnError(errors.New("database error"))

		err = repo.CreateSession(ctx, "user-1", "raw-token", expiresAt)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetSessionUser(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM sessions s JOIN users u").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "email_verified_at", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("user-1", "test@example.com", "hash", nil, "FREE", false, now, now))

		user, err := repo.GetSessionUser(ctx, "raw-token")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %s", user.ID)
		}
	})

	t.Run("session not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM sessions s JOIN users u").
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetSessionUser(ctx, "invalid-token")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestRevokeSession(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("UPDATE sessions SET revoked_at").
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err = repo.RevokeSession(ctx, "raw-token")
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

		mock.ExpectExec("UPDATE sessions SET revoked_at").
			WillReturnError(errors.New("database error"))

		err = repo.RevokeSession(ctx, "raw-token")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
