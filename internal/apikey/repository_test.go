package apikey

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

func TestHashAPIKey(t *testing.T) {
	hash1 := HashAPIKey("trimly_live_abc123")
	hash2 := HashAPIKey("trimly_live_abc123")

	if hash1 != hash2 {
		t.Error("expected deterministic hash")
	}

	if hash1 == "" {
		t.Error("expected non-empty hash")
	}
}

func TestCreateAPIKey(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("INSERT INTO api_keys").
			WithArgs("user-1", "trimly_liv", pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "key_prefix", "created_at"}).
				AddRow("key-1", "trimly_liv", now))

		resp, err := repo.CreateAPIKey(ctx, "user-1", "trimly_liv", "trimly_live_abc123")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if resp.ID != "key-1" {
			t.Errorf("expected key-1, got %s", resp.ID)
		}
		if resp.APIKey != "trimly_live_abc123" {
			t.Errorf("expected raw key to be returned")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("INSERT INTO api_keys").
			WillReturnError(errors.New("database error"))

		_, err = repo.CreateAPIKey(ctx, "user-1", "trimly_liv", "trimly_live_abc123")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetUserAPIKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM api_keys WHERE user_id").
			WithArgs("user-1").
			WillReturnRows(pgxmock.NewRows([]string{"id", "key_prefix", "created_at"}).
				AddRow("key-1", "trimly_liv", now).
				AddRow("key-2", "trimly_liv", now))

		keys, err := repo.GetUserAPIKeys(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("no keys", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_keys WHERE user_id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "key_prefix", "created_at"}))

		keys, err := repo.GetUserAPIKeys(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_keys WHERE user_id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		_, err = repo.GetUserAPIKeys(ctx, "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestRevokeAPIKey(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("UPDATE api_keys SET revoked_at").
			WithArgs("key-1", "user-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err = repo.RevokeAPIKey(ctx, "key-1", "user-1")
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

		mock.ExpectExec("UPDATE api_keys SET revoked_at").
			WillReturnError(errors.New("database error"))

		err = repo.RevokeAPIKey(ctx, "key-1", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestValidateAPIKey(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM api_keys k JOIN users u").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "email", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("key-1", "user-1", "user@example.com", "BUSINESS", false, now, now))

		user, apiKeyID, err := repo.ValidateAPIKey(ctx, "trimly_live_abc123")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %s", user.ID)
		}
		if apiKeyID != "key-1" {
			t.Errorf("expected key-1, got %s", apiKeyID)
		}
	})

	t.Run("key not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_keys k JOIN users u").
			WillReturnError(pgx.ErrNoRows)

		_, _, err = repo.ValidateAPIKey(ctx, "invalid-key")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("non-business plan", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM api_keys k JOIN users u").
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "email", "plan_code", "is_platform_admin", "created_at", "updated_at"}).
				AddRow("key-1", "user-1", "user@example.com", "FREE", false, now, now))

		_, _, err = repo.ValidateAPIKey(ctx, "trimly_live_abc123")
		if err == nil {
			t.Error("expected error for non-business plan, got nil")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_keys k JOIN users u").
			WillReturnError(errors.New("database error"))

		_, _, err = repo.ValidateAPIKey(ctx, "trimly_live_abc123")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestIncrementAndCheckDailyQuota(t *testing.T) {
	ctx := context.Background()

	t.Run("within quota", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO api_usage_daily.*ON CONFLICT").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"accepted_request_count"}).
				AddRow(100))
		mock.ExpectCommit()

		err = repo.IncrementAndCheckDailyQuota(ctx, "key-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("quota exceeded", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO api_usage_daily.*ON CONFLICT").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"accepted_request_count"}).
				AddRow(5001))
		mock.ExpectRollback()

		err = repo.IncrementAndCheckDailyQuota(ctx, "key-1")
		if err == nil {
			t.Error("expected error for quota exceeded, got nil")
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
		mock.ExpectQuery("INSERT INTO api_usage_daily.*ON CONFLICT").
			WillReturnError(errors.New("database error"))
		mock.ExpectRollback()

		err = repo.IncrementAndCheckDailyQuota(ctx, "key-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetAPIUsageHistory(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_usage_daily u JOIN api_keys k").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"api_key_id", "date", "accepted_request_count"}).
				AddRow("key-1", "2024-01-01", 100).
				AddRow("key-1", "2024-01-02", 200))

		history, err := repo.GetAPIUsageHistory(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(history) != 2 {
			t.Errorf("expected 2 records, got %d", len(history))
		}
	})

	t.Run("no history", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_usage_daily u JOIN api_keys k").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"api_key_id", "date", "accepted_request_count"}))

		history, err := repo.GetAPIUsageHistory(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(history) != 0 {
			t.Errorf("expected 0 records, got %d", len(history))
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM api_usage_daily u JOIN api_keys k").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		_, err = repo.GetAPIUsageHistory(ctx, "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
